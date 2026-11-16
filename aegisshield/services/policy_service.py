"""Generate a security policy with the model and render it as a PDF.

The page runs ``generate_policy`` in a job and stores the result in the
visitor's workspace. The model is reached through the ``LLMClient`` passed in,
on the architect model; mock mode is ``MockLLM``.

Model output and profile text are untrusted: the body is sanitized and
capped, and everything placed into the PDF's HTML is escaped. Images in the
model's markdown are removed before rendering so the PDF renderer never
fetches a URL or reads a local file.
"""

from __future__ import annotations

import base64
import dataclasses
import html
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisshield.config import Settings
from aegisshield.core.errors import AegisError, ValidationError
from aegisshield.core.text import sanitize_user_markdown, single_line
from aegisshield.llm.base import LLMClient, OnText
from aegisshield.safeguards import REPORT_KEY, Safeguards, Source
from aegisshield.safeguards import summary as safeguards_summary
from aegisshield.services import policy_catalog
from aegisshield.services.export_service import restrict_links
from aegisshield.services.markdown_render import MAX_RENDER_CHARS, render_markdown
from aegisshield.services.nist_csf_service import category_index
from aegisshield.services.org_profile import LeadershipContact, OrgProfile
from aegisshield.services.pdf_render import PdfRenderError, html_to_pdf, pdf_message

logger = logging.getLogger(__name__)

# Cap on a policy body, generated or edited: the most the bounded markdown
# renderer shows (``markdown_render.MAX_RENDER_CHARS``), so the PDF always
# holds the whole policy. A generated policy is at most about 35,000
# characters (POLICY_MAX_TOKENS).
MAX_BODY_CHARS = MAX_RENDER_CHARS
POLICY_MAX_TOKENS = 8192

SYSTEM_PROMPT = (
    "You are an expert GRC consultant. "
    "Write formal, actionable security policy documents in clean Markdown. "
    "Use the organization's actual name, leadership names/roles, industry, and "
    "compliance requirements throughout. "
    "Do NOT include any preamble, meta-commentary, or code fences; output the "
    "policy document body only. Do not use em dashes."
)

_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
# The logo for light backgrounds (navy artwork): documents are on white paper.
_LOGO_PATH = Path(__file__).resolve().parents[1] / "ui" / "assets" / "brand" / "logo-light.png"


class PolicyRenderError(AegisError):
    """The policy PDF could not be built."""


def resolve_csf_mappings(catalog_entry: Mapping[str, Any]) -> list[dict[str, str]]:
    """The entry's CSF baseline ids as ``{id, name, function_id, function_name}`` dicts.

    Unknown ids are logged and skipped.
    """
    index = category_index()
    result: list[dict[str, str]] = []
    for cid in catalog_entry.get("csf_baseline", []):
        cat = index.get(cid)
        if cat is None:
            logger.warning("policy catalog CSF id not found id=%s", cid)
            continue
        result.append({"id": cat.id, "name": cat.name, "function_id": cat.function_id,
                       "function_name": cat.function_name})
    return result


def _as_profile(org_profile: OrgProfile | Mapping[str, Any] | None) -> OrgProfile:
    if org_profile is None:
        # A policy is written for a saved organization profile.
        raise ValidationError("Save an organization profile before generating a policy.")
    if isinstance(org_profile, OrgProfile):
        return org_profile
    return OrgProfile.from_dict(org_profile)


def _find_role(profile: OrgProfile, *roles: str) -> str:
    for contact in profile.leadership:
        if contact.role in roles:
            return f"{contact.name} ({contact.role})"
    return "the designated executive"


def build_prompt(
    catalog_entry: Mapping[str, Any],
    profile: OrgProfile,
    citations: list[str] | None = None,
) -> str:
    """The user prompt: the entry's outline filled in from the profile.

    Profile values are substituted by ``str.format`` into the catalog's own
    template, so braces in visitor text are kept as text, never parsed.
    """
    leadership_text = (
        "; ".join(f"{c.role}: {c.name}" for c in profile.leadership) or "Leadership team"
    )
    drivers = ", ".join(profile.compliance_drivers) or "general best practices"
    notes = profile.regulatory_notes
    prompt = str(catalog_entry.get("prompt_outline", "")).format(
        legal_name=profile.legal_name,
        dba_name=profile.dba_name or profile.legal_name,
        industry=profile.industry or "technology",
        employee_count=profile.employee_count or "N",
        leadership_text=leadership_text,
        ceo_or_exec=_find_role(profile, "CEO", "COO"),
        ciso_or_exec=_find_role(profile, "CISO", "CTO"),
        compliance_drivers=drivers,
        regulatory_notes=f"Regulatory context: {notes}" if notes else "",
    ).strip()
    if citations:
        prompt += (
            "\n\nCite these where they apply (the organization selected the frameworks "
            "they come from):\n" + "\n".join(f"- {c}" for c in citations)
        )
    return prompt


def screen_org_profile(safeguards: Safeguards, profile: OrgProfile) -> OrgProfile:
    """``profile`` with its free text screened as ``Source.PROFILE``.

    Leadership roles are one of a fixed list and are left as they are. The
    result is built directly, not through ``OrgProfile.from_dict``, so a
    value the input rails fenced is not refused for its new length.
    """
    def screen(text: str) -> str:
        return safeguards.screen(Source.PROFILE, text)

    return dataclasses.replace(
        profile,
        legal_name=screen(profile.legal_name),
        dba_name=screen(profile.dba_name),
        industry=screen(profile.industry),
        leadership=tuple(LeadershipContact(role=c.role, name=screen(c.name)) for c in profile.leadership),
        compliance_drivers=tuple(screen(d) for d in profile.compliance_drivers),
        regulatory_notes=screen(profile.regulatory_notes),
    )


def generate_policy(
    policy_key: str,
    org_profile: OrgProfile | Mapping[str, Any] | None,
    *,
    llm: LLMClient,
    settings: Settings,
    on_text: OnText | None = None,
    safeguards: Safeguards | None = None,
) -> dict[str, Any]:
    """Write the catalog policy ``policy_key`` for the organization.

    Returns ``{title, body_markdown, csf_mappings, regulatory_citations}``.
    ``regulatory_citations`` holds only citations for the compliance drivers
    the profile selected. Raises ``ValidationError`` for an unknown key or a
    missing or invalid profile, and ``LLMError`` when the model fails.

    The organization profile's text is screened as ``Source.PROFILE`` and
    the answer passes the output rails (``safeguards`` None builds them from
    ``settings``); the record is the result's ``REPORT_KEY``. May raise
    ``SafeguardsStopped``.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)
    entry = policy_catalog.get_entry(policy_key)
    if entry is None:
        raise ValidationError("That policy is not in the catalog.")
    original = _as_profile(org_profile)
    citations = policy_catalog.citations_for(policy_key, original.compliance_drivers)
    profile = screen_org_profile(sg, original)
    logger.info("policy generate key=%s model=%s", policy_key, settings.architect_model)
    body = sg.wrap(llm).chat_text(
        system=SYSTEM_PROMPT,
        user=build_prompt(entry, profile, citations),
        model=settings.architect_model,
        max_tokens=POLICY_MAX_TOKENS,
        on_text=on_text,
    )
    return {
        "title": entry["title"],
        "body_markdown": sanitize_user_markdown(body, MAX_BODY_CHARS),
        "csf_mappings": resolve_csf_mappings(entry),
        "regulatory_citations": citations,
        REPORT_KEY: sg.report(),
    }


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def markdown_to_html(markdown_text: str) -> str:
    """Policy markdown as HTML, rendered in bounded time
    (``markdown_render.render_markdown``): raw HTML escaped, images removed,
    and links other than http, https, mailto, or a fragment reduced to their
    text (``export_service.restrict_links``)."""
    return restrict_links(_IMG_RE.sub("", render_markdown(markdown_text)))


def _logo_tag() -> str:
    try:
        data = _LOGO_PATH.read_bytes()
    except OSError:
        return ""
    encoded = base64.b64encode(data).decode("ascii")
    return f'<img src="data:image/png;base64,{encoded}" width="120" />'


def _text_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else []


_PDF_CSS = """
@page { size: letter; margin: 0.65in 0.6in; }
body { font-family: Helvetica, Arial, sans-serif; font-size: 11px; color: #1f2937; line-height: 1.5; }
h1 { color: #0c4a6e; font-size: 20px; margin: 4px 0 2px; }
h2 { color: #0c4a6e; font-size: 14px; margin: 14px 0 4px; padding-bottom: 2px; border-bottom: 1px solid #bdd7ee; }
h3 { color: #0c4a6e; font-size: 12px; margin: 10px 0 3px; }
p { margin: 4px 0; }
ul, ol { margin: 4px 0 4px 18px; padding: 0; }
li { margin: 2px 0; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 10px; }
th, td { border: 1px solid #cbd5e1; padding: 5px 6px; vertical-align: top; font-size: 10px; }
th { background: #e0f2fe; color: #0c4a6e; font-weight: 600; font-size: 9.5px; text-transform: uppercase; }
.cover { border-left: 4px solid #00cfff; background: #f0fdff; padding: 10px 14px; margin: 0 0 16px; }
.cover-title { color: #0c4a6e; font-size: 18px; font-weight: 700; margin: 4px 0 2px; }
.cover-meta { color: #475569; font-size: 9.5px; margin-top: 4px; }
.csf-section { margin: 10px 0 14px; }
.csf-label { font-size: 9px; color: #475569; text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
.badge { display: inline-block; background: #e0f2fe; color: #0c4a6e; border: 1px solid #bdd7ee;
  border-radius: 3px; padding: 1px 5px; font-size: 8.5px; margin: 1px 2px 1px 0; }
.badge-reg { background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }
"""


def build_policy_html(policy: Mapping[str, Any], *, now: datetime | None = None) -> str:
    """The HTML document ``render_policy_pdf`` converts; every value is escaped.

    ``policy`` holds ``title``, ``body_markdown``, and optionally ``version``,
    ``csf_mappings``, and ``regulatory_citations``.
    """
    title = single_line(policy.get("title") or "Security Policy", 200)
    version = policy.get("version", 1)
    generated = (now or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC")
    csf_badges = "".join(
        '<span class="badge">'
        f"{_escape(m.get('id', ''))} - {_escape(m.get('function_name', ''))}: "
        f"{_escape(m.get('name', ''))}</span> "
        for m in _text_list(policy.get("csf_mappings"))
        if isinstance(m, Mapping)
    )
    reg_badges = "".join(
        f'<span class="badge badge-reg">{_escape(c)}</span> '
        for c in _text_list(policy.get("regulatory_citations"))
    )
    csf_html = (
        f'<div class="csf-section"><div class="csf-label">NIST CSF 2.0 Mappings</div>'
        f"{csf_badges}</div>"
        if csf_badges
        else ""
    )
    reg_html = (
        f'<div class="csf-section"><div class="csf-label">Regulatory Citations</div>'
        f"{reg_badges}</div>"
        if reg_badges
        else ""
    )
    body_html = markdown_to_html(str(policy.get("body_markdown") or ""))
    summary_html = safeguards_summary.as_html(policy.get(REPORT_KEY), with_flags=False,
                                              edited=bool(policy.get("edited")))
    checks_html = (
        f'<div class="csf-section"><div class="csf-label">Safeguards</div>{summary_html}</div>'
        if REPORT_KEY in policy else ""
    )
    return f"""<html>
<head><meta charset="utf-8" /><style>{_PDF_CSS}</style></head>
<body>
  <div class="cover">
    {_logo_tag()}
    <p class="cover-title">{_escape(title)}</p>
    <div class="cover-meta">Version {_escape(version)} | Generated: {_escape(generated)}</div>
  </div>
  {csf_html}
  {reg_html}
  {body_html}
  {checks_html}
</body>
</html>"""


def policy_markdown_export(policy: Mapping[str, Any]) -> str:
    """The policy body as a Markdown download, with the safeguards summary after it."""
    body = str(policy.get("body_markdown") or "")
    if REPORT_KEY not in policy:
        return body
    checks = safeguards_summary.as_markdown(policy.get(REPORT_KEY), with_flags=False,
                                            edited=bool(policy.get("edited")))
    return f"{body.rstrip()}\n\n---\n\n{checks}"


def render_policy_pdf(policy: Mapping[str, Any]) -> bytes:
    """Render a policy dict (see ``build_policy_html``) to PDF bytes.

    Drawn by ``pdf_render.html_to_pdf``, which fetches and reads nothing.
    Raises ``PolicyRenderError`` when the PDF is refused or xhtml2pdf fails,
    with the renderer's sentence when it names a reason.
    """
    try:
        return html_to_pdf(build_policy_html(policy))
    except PdfRenderError as exc:
        raise PolicyRenderError(pdf_message(exc, "The policy PDF could not be generated.")) from exc


__all__ = [
    "policy_markdown_export",
    "MAX_BODY_CHARS",
    "PolicyRenderError",
    "SYSTEM_PROMPT",
    "build_policy_html",
    "build_prompt",
    "generate_policy",
    "markdown_to_html",
    "render_policy_pdf",
    "resolve_csf_mappings",
]
