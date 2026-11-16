"""Structured exports of a finished threat model: JSON, HTML, and SARIF 2.1.0.

- ``to_json_report`` returns a schema-stable dict of every artifact, for
  storage or downstream automation; ``to_json_bytes`` serializes it.
- ``to_html_report`` returns one self-contained HTML document with no
  external assets and a Content-Security-Policy that blocks scripts, so it is
  safe to email or attach to a ticket.
- ``to_sarif`` returns a SARIF 2.1.0 document so threats can be loaded into
  code scanning dashboards and IDE tools.

Each exporter takes the job result dict the threat-model pipeline returns,
the request's application profile and description, and optionally a NIST CSF
mapping and a vulnerability lookup result to include as sections.

Model output and visitor text are untrusted. Every string placed into HTML is
escaped; markdown is rendered with raw HTML escaped, images reduced to their
alt text, and only http(s) links kept. The section renderers here are shared
with ``report_service`` (the PDF report).
"""

from __future__ import annotations

import dataclasses
import hashlib
import html
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from aegisshield import __version__
from aegisshield.core.text import clean_text, is_safe_link, strip_invisible
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY
from aegisshield.pipeline.formatting_service import atlas_mapping_export, atlas_mapping_to_markdown
from aegisshield.safeguards import summary as safeguards_summary
from aegisshield.services.markdown_render import render_markdown

SCHEMA_VERSION = "1"

_TOOL_NAME = "AegisShield"
_TOOL_INFO_URI = "https://github.com/mgrofsky/AegisShield"
_DEFAULT_LEVEL = "warning"
_UNKNOWN = "unknown"
_NONE_MARK = "-"
_CVE_DESCRIPTION_CHARS = 300
# OTX tags shown per report in an export; the rest are counted as "...".
_OTX_TAGS = 8

# Result keys copied into the JSON report, in this order. The last four are
# present only when the matching add-on ran.
_RESULT_KEYS = (
    "threat_model",
    "improvement_suggestions",
    "threat_model_markdown",
    "mitre_attack_markdown",
    "nvd_vulnerabilities_markdown",
    "otx_data_markdown",
    "attack_tree_code",
    "mitre_data",
    "detected_patterns",
    "pattern_source",
    "mitigations_markdown",
    "dread_assessment",
    "dread_assessment_markdown",
    "test_cases_markdown",
)
_LIST_KEYS = frozenset({"threat_model", "improvement_suggestions", "mitre_data", "detected_patterns"})
_DREAD_KEYS = (
    "Damage Potential",
    "Reproducibility",
    "Exploitability",
    "Affected Users",
    "Discoverability",
)
# STRIDE category to the letter used in threat IDs (TC-S01). Same rule as the
# pipeline's ID stamping, used only when a threat arrives without an ID.
_STRIDE_LETTERS = (
    ("spoofing", "S"),
    ("tampering", "T"),
    ("repudiation", "R"),
    ("disclosure", "I"),
    ("denial of service", "D"),
    ("dos", "D"),
    ("elevation of privilege", "E"),
    ("privilege escalation", "E"),
    ("eop", "E"),
)
# markdown2 emits <img> only for markdown image syntax (raw tags are escaped).
# Images could load a remote URL or a local file, so each becomes its alt text.
_MD_IMG_RE = re.compile(r'<img\s[^>]*?alt="([^"]*)"[^>]*?/?>|<img\s[^>]*?/?>')
# markdown2 writes every link as <a href="..." ...>text</a>, with the target
# in double quotes; raw <a> tags in the text are escaped, so these are its own.
_MD_ANCHOR_RE = re.compile(r"<a\s([^>]*)>(.*?)</a>", re.DOTALL)
_HREF_RE = re.compile(r'href="([^"]*)"')
_RULE_ID_UNSAFE_RE = re.compile(r"[^A-Za-z0-9]")
_TECHNIQUE_ID_RE = re.compile(r"^(?:AML\.)?T\d{4}(?:\.\d{3})?$")


# ---------------------------------------------------------------------------
# Shared helpers (also used by report_service)
# ---------------------------------------------------------------------------


def escape(value: Any) -> str:
    """HTML-escaped display text for any value; None becomes an empty string."""
    if value is None:
        return ""
    return html.escape(strip_invisible(clean_text(str(value))), quote=True)


def restrict_links(rendered: str) -> str:
    """Rendered markdown2 HTML with every link whose target is not allowed
    (``core.text.is_safe_link``: http, https, mailto, or a fragment)
    replaced by its text."""

    def keep(match: re.Match[str]) -> str:
        href = _HREF_RE.search(match.group(1))
        return match.group(0) if href and is_safe_link(href.group(1)) else match.group(2)

    return _MD_ANCHOR_RE.sub(keep, rendered)


def markdown_html(text: str | None) -> str:
    """Render untrusted markdown to HTML that cannot carry markup of its own.

    Rendered in bounded time by ``markdown_render.render_markdown`` (raw HTML
    escaped, at most ``MAX_RENDER_CHARS`` characters, hostile parts shown as
    plain text). A link keeps its target only when ``restrict_links`` allows
    it (otherwise only its text is left), and images become their alt text.
    """
    rendered = render_markdown(text)
    if not rendered:
        return ""
    return restrict_links(_MD_IMG_RE.sub(lambda m: m.group(1) or "", rendered))


def safe_link(url: Any, label: Any) -> str:
    """An ``<a>`` to ``url`` when it is http(s), otherwise the escaped label alone."""
    text = escape(label)
    if isinstance(url, str) and url.strip().lower().startswith(("https://", "http://")):
        return f'<a href="{escape(url.strip())}">{text}</a>'
    return text


def format_count(value: Any) -> str:
    """A count for display. None (and anything not a number) means unknown, never 0."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return _UNKNOWN
    return str(int(value)) if float(value).is_integer() else str(value)


def threat_id(threat: Mapping[str, Any], fallback: str = "") -> str:
    """The threat's ``ID`` field, or ``fallback`` when it has none."""
    value = threat.get("ID")
    return str(value).strip() if value not in (None, "") else fallback


def assign_missing_ids(threats: list[Any]) -> list[str]:
    """IDs for ``threats`` in order, deriving ``TC-<letter><nn>`` where one is missing.

    The pipeline stamps IDs before it returns; this keeps the DREAD join and
    the tables usable for a result that skipped that step. Inputs are not
    changed.
    """
    counters: dict[str, int] = {}
    ids: list[str] = []
    for threat in threats:
        if not isinstance(threat, Mapping):
            ids.append("")
            continue
        kind = str(threat.get("Threat Type") or "").strip().lower()
        letter = next((ltr for key, ltr in _STRIDE_LETTERS if key in kind), "X")
        counters[letter] = counters.get(letter, 0) + 1
        ids.append(threat_id(threat, f"TC-{letter}{counters[letter]:02d}"))
    return ids


def _threats(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = result.get("threat_model")
    return [t for t in value if isinstance(t, dict)] if isinstance(value, list) else []


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item not in (None, "")]


def _text(result: Mapping[str, Any], key: str) -> str:
    value = result.get(key)
    return value if isinstance(value, str) else ""


def _as_dict(value: Any) -> Any:
    """``value`` as plain data: dataclass instances become dicts."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def _assumption_text(assumption: Any) -> str:
    if isinstance(assumption, str):
        return escape(assumption)
    if not isinstance(assumption, Mapping):
        return ""
    main = assumption.get("Assumption") or assumption.get("name") or assumption.get("text")
    extras = [
        f"{label}: {escape(assumption[key])}"
        for key, label in (("Role", "Role"), ("Condition", "Condition"))
        if assumption.get(key)
    ]
    body = escape(main) if main else ""
    if extras:
        body = f"{body} ({', '.join(extras)})" if body else ", ".join(extras)
    return body


def threat_table_html(threats: list[dict[str, Any]]) -> str:
    """The threat model as an HTML table (ID, type, scenario, assumptions, impact)."""
    if not threats:
        return '<p class="muted">No threats were identified.</p>'
    ids = assign_missing_ids(threats)
    rows: list[str] = []
    for tid, threat in zip(ids, threats, strict=True):
        raw = threat.get("Assumptions")
        items = [_assumption_text(a) for a in raw] if isinstance(raw, list) else []
        items = [f"<li>{item}</li>" for item in items if item]
        assumptions = f"<ul>{''.join(items)}</ul>" if items else '<span class="muted">None stated</span>'
        rows.append(
            "<tr>"
            f'<td class="tid">{escape(tid or _NONE_MARK)}</td>'
            f"<td>{escape(threat.get('Threat Type') or 'N/A')}</td>"
            f"<td>{escape(threat.get('Scenario') or 'N/A')}</td>"
            f"<td>{assumptions}</td>"
            f"<td>{escape(threat.get('Potential Impact') or 'N/A')}</td>"
            "</tr>"
        )
    return (
        '<table class="threat-table"><thead><tr>'
        "<th>ID</th><th>Threat Type</th><th>Scenario</th><th>Assumptions</th>"
        "<th>Potential Impact</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def profile_html(profile: Mapping[str, Any], app_description: str) -> str:
    """The application profile as a key/value table, the description, and technologies."""

    def joined(value: Any) -> str:
        if isinstance(value, list | tuple):
            return ", ".join(str(v) for v in value if v not in (None, "")) or _NONE_MARK
        return str(value) if value not in (None, "") else _NONE_MARK

    def field(key: str) -> str:
        value = profile.get(key)
        return str(value) if value not in (None, "") else "N/A"

    rows = (
        ("Application Type", field("app_type")),
        ("Industry Sector", field("industry_sector")),
        ("Sensitive Data", field("sensitive_data")),
        ("Internet Facing", field("internet_facing")),
        ("Employees", field("num_employees")),
        ("Authentication", joined(profile.get("authentication"))),
        ("Compliance", joined(profile.get("compliance_requirements"))),
    )
    kv = "".join(
        f'<tr><td class="k">{escape(label)}</td><td class="v">{escape(value)}</td></tr>'
        for label, value in rows
    )
    techs = profile.get("selected_technologies")
    versions = profile.get("selected_versions")
    versions = versions if isinstance(versions, Mapping) else {}
    names = list(techs) if isinstance(techs, Mapping | list | tuple) else []
    tech_items = "".join(
        f"<li><strong>{escape(name)}</strong>: "
        f"{escape(versions.get(name) or 'No version specified')}</li>"
        for name in names
    ) or '<li class="muted">No technologies selected</li>'
    description = markdown_html(app_description) or '<p class="muted">No description given.</p>'
    return (
        f'<table class="kv">{kv}</table>'
        f"<h3>Application Description</h3>{description}"
        f"<h3>Selected Technologies</h3><ul>{tech_items}</ul>"
    )


def suggestions_html(suggestions: list[str]) -> str:
    """Improvement suggestions as an escaped list."""
    items = "".join(f"<li>{escape(item)}</li>" for item in suggestions)
    return f"<ul>{items or '<li>No improvement suggestions provided.</li>'}</ul>"


def csf_section_html(nist_csf: Mapping[str, Any] | None) -> str:
    """The NIST CSF 2.0 mapping as HTML, or "" when there is none.

    Accepts ``{"mappings": [...], "coverage": {...}}`` as the NIST CSF service
    and its route produce it (mapping rows may also be dataclass instances).
    The service's own ``markdown`` is not used; the tables are built here so
    every value is escaped.
    """
    if not isinstance(nist_csf, Mapping):
        return ""
    coverage = nist_csf.get("coverage")
    raw_mappings = nist_csf.get("mappings")
    mappings = [_as_dict(m) for m in raw_mappings] if isinstance(raw_mappings, list) else []
    mappings = [m for m in mappings if isinstance(m, Mapping)]
    parts: list[str] = []
    if isinstance(coverage, Mapping) and coverage:
        rows = []
        for fn_id, info in coverage.items():
            info = info if isinstance(info, Mapping) else {}
            cats = info.get("categories")
            cats_text = ", ".join(str(c) for c in cats) if isinstance(cats, list) and cats else _NONE_MARK
            rows.append(
                "<tr>"
                f'<td class="tid">{escape(fn_id)}</td>'
                f"<td>{escape(info.get('name') or fn_id)}</td>"
                f"<td>{escape(format_count(info.get('threat_count')))}</td>"
                f"<td>{escape(cats_text)}</td>"
                "</tr>"
            )
        parts.append(
            "<h3>Coverage by Function</h3><table><thead><tr><th>Function</th><th>Name</th>"
            f"<th>Threats</th><th>Categories</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
        )
    if mappings:
        rows = []
        for mapping in mappings:
            raw_cats = mapping.get("categories")
            cats = [_as_dict(c) for c in raw_cats] if isinstance(raw_cats, list) else []
            cat_text = ", ".join(
                f"{c.get('id', '')} ({c.get('function_name', '')})"
                for c in cats
                if isinstance(c, Mapping)
            )
            rows.append(
                "<tr>"
                f'<td class="tid">{escape(mapping.get("threat_id") or _NONE_MARK)}</td>'
                f"<td>{escape(mapping.get('threat_type') or _NONE_MARK)}</td>"
                f"<td>{escape(mapping.get('scenario') or _NONE_MARK)}</td>"
                f"<td>{escape(mapping.get('technique_id') or _NONE_MARK)}</td>"
                f"<td>{escape(cat_text or _NONE_MARK)}</td>"
                "</tr>"
            )
        parts.append(
            "<h3>Threats Mapped to Categories</h3><table><thead><tr><th>ID</th><th>STRIDE</th>"
            "<th>Scenario</th><th>Technique</th><th>NIST CSF</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
    return "".join(parts)


def _kev_text(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return _UNKNOWN


def _percent(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return _NONE_MARK
    return f"{value * 100:.1f}%"


def _cve_table(cves: list[Any]) -> str:
    rows = []
    for cve in cves:
        if not isinstance(cve, Mapping):
            continue
        score = cve.get("cvss_score")
        score_text = str(score) if isinstance(score, int | float) and not isinstance(score, bool) else _NONE_MARK
        description = clean_text(str(cve.get("description") or ""))
        if len(description) > _CVE_DESCRIPTION_CHARS:
            description = description[: _CVE_DESCRIPTION_CHARS - 3].rstrip() + "..."
        rows.append(
            "<tr>"
            f'<td class="tid">{safe_link(cve.get("url"), cve.get("cve_id") or _NONE_MARK)}</td>'
            f"<td>{escape(cve.get('severity') or _NONE_MARK)}</td>"
            f"<td>{escape(score_text)}</td>"
            f"<td>{escape(_kev_text(cve.get('known_exploited')))}</td>"
            f"<td>{escape(_percent(cve.get('epss')))}</td>"
            f"<td>{escape(cve.get('published') or _NONE_MARK)}</td>"
            f"<td>{escape(description)}</td>"
            "</tr>"
        )
    if not rows:
        return ""
    return (
        "<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>EPSS</th>"
        f"<th>Published</th><th>Description</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _otx_item(pulse: Mapping[str, Any]) -> str:
    """One OTX report: its name (linked when the URL is http(s)), TLP, date, tags."""
    details = []
    if pulse.get("tlp"):
        details.append(f"TLP {escape(pulse.get('tlp'))}")
    if pulse.get("modified"):
        details.append(f"updated {escape(str(pulse.get('modified'))[:10])}")
    tags = [t for t in pulse.get("tags") or [] if isinstance(t, str) and t.strip()] \
        if isinstance(pulse.get("tags"), list) else []
    if tags:
        shown = ", ".join(escape(t) for t in tags[:_OTX_TAGS])
        details.append(f"tags: {shown}{', ...' if len(tags) > _OTX_TAGS else ''}")
    meta = f' <span class="muted">({"; ".join(details)})</span>' if details else ""
    return f"<li>{safe_link(pulse.get('url'), pulse.get('name') or 'OTX report')}{meta}</li>"


def _tech_html(tech: Mapping[str, Any]) -> str:
    name = tech.get("product_name") or tech.get("name") or "Unnamed technology"
    version = tech.get("version") or tech.get("lookup_version")
    title = f"{name} {version}" if version else str(name)
    counts = (
        ("CVEs", tech.get("cve_count")),
        ("Critical", tech.get("critical_count")),
        ("High", tech.get("high_count")),
        ("Known exploited", tech.get("kev_count")),
    )
    count_text = " &middot; ".join(f"{escape(k)}: {escape(format_count(v))}" for k, v in counts)
    parts = [
        f"<h4>{escape(title)}</h4>",
        f"<p>{escape(tech.get('description') or '')}</p>" if tech.get("description") else "",
        f'<p class="meta">{count_text}</p>',
    ]
    if tech.get("note"):
        parts.append(f'<p class="muted">{escape(tech.get("note"))}</p>')
    eol = tech.get("eol")
    if isinstance(eol, Mapping) and eol:
        is_eol = eol.get("is_eol")
        state = "End of life" if is_eol is True else "Supported" if is_eol is False else "Support status unknown"
        details = []
        if eol.get("cycle"):
            details.append(f"release {eol.get('cycle')}")
        if eol.get("eol"):
            details.append(f"end of life {eol.get('eol')}")
        label = f"{state} ({', '.join(details)})" if details else state
        parts.append(f"<p>{safe_link(eol.get('url'), label)}</p>")
    cves = tech.get("cves")
    if isinstance(cves, list):
        parts.append(_cve_table(cves))
    exploits = tech.get("exploits")
    exploit_items = [
        f"<li>{escape(e.get('cve_id') or _NONE_MARK)}: "
        f"{safe_link(e.get('url'), e.get('title') or e.get('edb_id') or 'Exploit')}</li>"
        for e in (exploits if isinstance(exploits, list) else [])
        if isinstance(e, Mapping)
    ]
    if exploit_items:
        parts.append(f"<p>Public exploits:</p><ul>{''.join(exploit_items)}</ul>")
    otx_items = [_otx_item(p) for p in tech.get("otx_pulses") or [] if isinstance(p, Mapping)] \
        if isinstance(tech.get("otx_pulses"), list) else []
    if otx_items:
        parts.append(f"<p>AlienVault OTX reports that mention it:</p><ul>{''.join(otx_items)}</ul>")
    errors = tech.get("errors")
    if isinstance(errors, Mapping) and errors:
        items = "".join(f"<li>{escape(src)}: {escape(msg)}</li>" for src, msg in errors.items())
        parts.append(f'<p class="muted">Some sources did not answer:</p><ul>{items}</ul>')
    return f'<div class="tech">{"".join(parts)}</div>'


def vuln_section_html(vuln_lookup: Mapping[str, Any] | None) -> str:
    """The passive vulnerability lookup result as HTML, or "" when there is none.

    Counts that are None are shown as "unknown", never as 0.
    """
    if not isinstance(vuln_lookup, Mapping):
        return ""
    parts: list[str] = []
    status = vuln_lookup.get("status")
    if status and status != "complete":
        parts.append(
            f'<p class="muted">The lookup did not finish (status: {escape(status)}); '
            "results below are partial.</p>"
        )
    times = [
        f"{label} {escape(vuln_lookup.get(key))}"
        for key, label in (("started_at", "Started"), ("finished_at", "finished"))
        if vuln_lookup.get(key)
    ]
    if times:
        parts.append(f'<p class="meta">{", ".join(times)}.</p>')
    summary = vuln_lookup.get("summary")
    if isinstance(summary, Mapping):
        labels = (
            ("tech_count", "Technologies"),
            ("checked_count", "Checked"),
            ("not_checked_count", "Not checked"),
            ("cve_count", "CVEs"),
            ("critical_count", "Critical"),
            ("high_count", "High"),
            ("kev_count", "Known exploited (KEV)"),
            ("exploit_count", "Public exploits"),
            ("eol_count", "End of life"),
        )
        kv = "".join(
            f'<tr><td class="k">{escape(label)}</td>'
            f'<td class="v">{escape(format_count(summary.get(key)))}</td></tr>'
            for key, label in labels
        )
        parts.append(f'<table class="kv">{kv}</table>')
    techs = vuln_lookup.get("technologies")
    tech_list = [t for t in techs if isinstance(t, Mapping)] if isinstance(techs, list) else []
    parts.extend(_tech_html(t) for t in tech_list)
    if not tech_list:
        parts.append('<p class="muted">No technologies were looked up.</p>')
    return "".join(parts)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_json_report(
    result: Mapping[str, Any],
    app_profile: Mapping[str, Any] | None,
    app_description: str,
    *,
    nist_csf: Mapping[str, Any] | None = None,
    vuln_lookup: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Every artifact of the threat model as one JSON-ready dict.

    Missing result keys get an empty value of the right type so the schema is
    stable; the optional sections are ``null`` when not given.
    """
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "app_profile": dict(app_profile or {}),
        "app_description": app_description or "",
    }
    for key in _RESULT_KEYS:
        value = result.get(key)
        if key in _LIST_KEYS:
            report[key] = list(value) if isinstance(value, list) else []
        elif key == "dread_assessment":
            report[key] = value if isinstance(value, Mapping) else None
        else:
            report[key] = value if isinstance(value, str) else ""
    report["nist_csf"] = _as_dict(nist_csf) if nist_csf is not None else None
    if isinstance(report["nist_csf"], Mapping) and isinstance(report["nist_csf"].get("mappings"), list):
        report["nist_csf"] = {
            **report["nist_csf"],
            "mappings": [_as_dict(m) for m in report["nist_csf"]["mappings"]],
        }
    report["vulnerability_lookup"] = dict(vuln_lookup) if vuln_lookup is not None else None
    safeguards = result.get("safeguards")
    flags = result.get("review_flags")
    report["safeguards"] = dict(safeguards) if isinstance(safeguards, Mapping) else None
    report["review_flags"] = list(flags) if isinstance(flags, list) else []
    report["safeguards_summary"] = safeguards_summary.as_markdown(report["safeguards"], report["review_flags"])
    # An AI system's ATLAS block; absent for any other system, so its report is unchanged.
    atlas = atlas_mapping_export(result.get(ATLAS_RESULT_KEY))
    if atlas is not None:
        report[ATLAS_RESULT_KEY] = atlas
    return report


def to_json_bytes(report: Mapping[str, Any]) -> bytes:
    """UTF-8 JSON for a report from ``to_json_report`` (dates become strings)."""
    return json.dumps(report, ensure_ascii=False, indent=2, default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

# Scripts, frames, and remote loads are refused even if markup slipped past
# the escaping; only inline styles and data: images are allowed.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

_HTML_STYLE = """
    body { font-family: -apple-system, system-ui, "Segoe UI", sans-serif; max-width: 980px;
           margin: 2rem auto; padding: 0 1rem; color: #1f2937; line-height: 1.5; }
    header { border: 1px solid #cbd5e1; border-left: 4px solid #0c4a6e; background: #f8fafc;
             padding: 0.8rem 1.1rem; margin-bottom: 1.5rem; }
    h1 { color: #0c4a6e; margin: 0 0 0.3rem; font-size: 1.6rem; }
    h2 { color: #0c4a6e; border-bottom: 1px solid #bdd7ee; padding-bottom: 0.2rem; margin-top: 2rem; }
    h3 { color: #0c4a6e; } h4 { color: #334155; margin-bottom: 0.2rem; }
    table { border-collapse: collapse; width: 100%; margin: 0.8rem 0; }
    th, td { border: 1px solid #cbd5e1; padding: 0.4rem 0.6rem; vertical-align: top; text-align: left; }
    th { background: #e0f2fe; color: #0c4a6e; font-size: 0.85em; text-transform: uppercase; }
    table.kv td { border: none; padding: 0.15rem 0.4rem; } table.kv td.k { color: #475569; width: 30%; font-weight: 600; }
    td.tid { font-family: ui-monospace, Menlo, monospace; font-weight: 700; color: #0c4a6e; white-space: nowrap; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 0.8rem; overflow: auto; white-space: pre-wrap; }
    code { background: #f1f5f9; padding: 0 0.25rem; }
    .meta { color: #475569; font-size: 0.9em; } .muted { color: #64748b; font-style: italic; }
    .tech { border-top: 1px solid #e2e8f0; margin-top: 1rem; }
"""


def _html_section(title: str, body: str) -> str:
    content = body if body.strip() else '<p class="muted">No data.</p>'
    return f"<section><h2>{escape(title)}</h2>{content}</section>"


def _atlas_section(result: Mapping[str, Any]) -> list[str]:
    """The "MITRE ATLAS" section for an AI system; nothing for any other result."""
    block = atlas_mapping_to_markdown(result.get(ATLAS_RESULT_KEY))
    return [_html_section("MITRE ATLAS", markdown_html(block))] if block else []


def to_html_report(
    result: Mapping[str, Any],
    app_profile: Mapping[str, Any] | None,
    app_description: str,
    *,
    nist_csf: Mapping[str, Any] | None = None,
    vuln_lookup: Mapping[str, Any] | None = None,
) -> str:
    """One self-contained HTML document of the threat model.

    Core sections always appear (with "No data." when empty); the NIST CSF
    and vulnerability lookup sections appear only when given.
    """
    profile = app_profile or {}
    app_type = profile.get("app_type") or "Application"
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    attack_tree = _text(result, "attack_tree_code")
    sections = [
        _html_section("Application Profile", profile_html(profile, app_description)),
        _html_section("Improvement Suggestions", suggestions_html(_str_list(result.get("improvement_suggestions")))),
        _html_section("Threat Model", threat_table_html(_threats(result))),
        _html_section(
            "Attack Tree (Mermaid source)",
            f"<pre>{escape(attack_tree)}</pre>" if attack_tree.strip() else "",
        ),
        _html_section("Mitigations", markdown_html(_text(result, "mitigations_markdown"))),
        _html_section("DREAD Risk Assessment", markdown_html(_text(result, "dread_assessment_markdown"))),
        _html_section("Security Test Cases", markdown_html(_text(result, "test_cases_markdown"))),
        _html_section("MITRE ATT&CK and ATLAS", markdown_html(_text(result, "mitre_attack_markdown"))),
        *_atlas_section(result),
        _html_section("NVD Vulnerabilities", markdown_html(_text(result, "nvd_vulnerabilities_markdown"))),
        _html_section("AlienVault OTX", markdown_html(_text(result, "otx_data_markdown"))),
    ]
    if nist_csf is not None:
        sections.append(_html_section("NIST CSF 2.0 Mapping", csf_section_html(nist_csf)))
    if vuln_lookup is not None:
        sections.append(_html_section("Vulnerability Lookup", vuln_section_html(vuln_lookup)))
    sections.insert(1, _html_section("Safeguards", safeguards_summary.as_html(
        result.get("safeguards"), result.get("review_flags"))))
    meta = " &middot; ".join(
        f"<span><strong>{label}:</strong> {escape(value)}</span>"
        for label, value in (
            ("Generated", generated),
            ("Application", app_type),
            ("Industry", profile.get("industry_sector") or "N/A"),
        )
    )
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>AegisShield Threat Model: {escape(app_type)}</title>\n"
        f"<style>{_HTML_STYLE}</style>\n</head>\n<body>\n"
        f'<header><h1>Threat Modeling Report</h1><p class="meta">{meta}</p></header>\n'
        + "\n".join(sections)
        + "\n</body>\n</html>\n"
    )


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def _plain(value: Any) -> str:
    """Untrusted text for SARIF: no control, bidirectional, or invisible characters."""
    return strip_invisible(clean_text(str(value or ""))).strip()


def _dread_to_level(dread_value: Any) -> str:
    """SARIF level for a DREAD risk score (1 to 10): 8+ error, 5+ warning, else note."""
    if isinstance(dread_value, bool):
        return _DEFAULT_LEVEL
    try:
        score = float(dread_value)
    except (TypeError, ValueError):
        return _DEFAULT_LEVEL
    if score >= 8:
        return "error"
    if score >= 5:
        return "warning"
    return "note"


def _stable_fingerprint(threat: Mapping[str, Any]) -> str:
    """Stable across runs of the same input, so SARIF results dedupe correctly."""
    seed = (
        f"{threat.get('Threat Type', '')}|"
        f"{threat.get('Scenario', '')}|"
        f"{threat.get('Potential Impact', '')}"
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _help_uri(rule_id: str) -> str:
    if rule_id.startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{rule_id}"
    if rule_id.startswith("T") and rule_id[1:].split(".")[0].isdigit():
        return f"https://attack.mitre.org/techniques/{rule_id.replace('.', '/')}"
    return _TOOL_INFO_URI


def _build_rules(
    mitre_data: list[Any],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """SARIF rules from the first mapped technique of each threat.

    Returns ``(rules, fingerprint_to_rule_id)``. Rule IDs are technique IDs
    (``T1059``, ``AML.T0051``); a threat with no mapped technique gets a
    synthetic ``AEGIS.STRIDE.<type>`` rule.
    """
    rules: dict[str, dict[str, Any]] = {}
    rule_for_threat: dict[str, str] = {}
    for entry in mitre_data:
        if not isinstance(entry, Mapping):
            continue
        threat = entry.get("threat") if isinstance(entry.get("threat"), Mapping) else {}
        techniques = entry.get("mitre_techniques") if isinstance(entry.get("mitre_techniques"), list) else []
        tech = techniques[0] if techniques and isinstance(techniques[0], Mapping) else None
        fingerprint = _stable_fingerprint(threat)
        candidate = _plain(tech.get("technique_id") or tech.get("id")) if tech else ""
        if tech and _TECHNIQUE_ID_RE.match(candidate):
            rule_id = candidate
            name = _plain(tech.get("name")) or rule_id
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": name,
                    "shortDescription": {"text": name},
                    "fullDescription": {"text": _plain(tech.get("description"))},
                    "helpUri": _help_uri(rule_id),
                    "properties": {
                        "framework": _plain(tech.get("framework")) or "ATT&CK",
                        "tactic": _plain(tech.get("tactic")) or "Unknown",
                    },
                },
            )
        else:
            kind = _plain(threat.get("Threat Type")) or "Unknown"
            rule_id = f"AEGIS.STRIDE.{_RULE_ID_UNSAFE_RE.sub('', kind) or 'Unknown'}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f"STRIDE: {kind}",
                    "shortDescription": {"text": f"STRIDE category {kind}"},
                    "fullDescription": {
                        "text": "Threat without a mapped MITRE ATT&CK or ATLAS technique."
                    },
                    "properties": {"framework": "STRIDE"},
                },
            )
        rule_for_threat[fingerprint] = rule_id
    return list(rules.values()), rule_for_threat


def _parse_dread_scores(markdown: str) -> dict[str, float]:
    """Risk score per threat ID from the DREAD markdown table.

    The table is ``| ID | Damage | Reproducibility | ... | Risk Score |``. Rows
    whose last cell is not a number (the header and separator) are skipped.
    """
    scores: dict[str, float] = {}
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 7 or not cells[0]:
            continue
        try:
            scores[cells[0]] = float(cells[-1])
        except ValueError:
            continue
    return scores


def _dread_scores(result: Mapping[str, Any]) -> dict[str, float]:
    """Risk score per threat ID: the structured assessment first, the markdown second.

    They are keyed by threat ID because the DREAD output carries only the
    threat ID; a lookup by scenario text would make every result fall back to
    ``warning``.
    """
    scores = _parse_dread_scores(_text(result, "dread_assessment_markdown"))
    assessment = result.get("dread_assessment")
    rows = assessment.get("Risk Assessment") if isinstance(assessment, Mapping) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping) or not row.get("ID"):
            continue
        try:
            values = [float(row[key]) for key in _DREAD_KEYS]
        except (KeyError, TypeError, ValueError):
            continue
        scores[str(row["ID"]).strip()] = sum(values) / len(values)
    return scores


def _csf_by_threat(nist_csf: Mapping[str, Any] | None) -> dict[str, list[str]]:
    if not isinstance(nist_csf, Mapping) or not isinstance(nist_csf.get("mappings"), list):
        return {}
    out: dict[str, list[str]] = {}
    for mapping in (_as_dict(m) for m in nist_csf["mappings"]):
        if not isinstance(mapping, Mapping) or not mapping.get("threat_id"):
            continue
        cats = mapping.get("categories") if isinstance(mapping.get("categories"), list) else []
        ids = [_plain(_as_dict(c).get("id")) for c in cats if isinstance(_as_dict(c), Mapping)]
        out[str(mapping["threat_id"])] = [i for i in ids if i]
    return out


def _result_message(threat: Mapping[str, Any]) -> str:
    scenario = _plain(threat.get("Scenario"))
    impact = _plain(threat.get("Potential Impact"))
    if impact:
        return f"{scenario} (Potential impact: {impact})"
    return scenario or "AegisShield threat without scenario text."


def _cve_level(cve: Mapping[str, Any]) -> str:
    if cve.get("known_exploited") is True:
        return "error"
    severity = str(cve.get("severity") or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note" if severity == "LOW" else _DEFAULT_LEVEL


def _cve_results(
    vuln_lookup: Mapping[str, Any] | None, rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """One SARIF result per CVE in the lookup, with one rule per CVE ID."""
    if not isinstance(vuln_lookup, Mapping) or not isinstance(vuln_lookup.get("technologies"), list):
        return []
    results: list[dict[str, Any]] = []
    for tech in vuln_lookup["technologies"]:
        if not isinstance(tech, Mapping) or not isinstance(tech.get("cves"), list):
            continue
        tech_name = _plain(tech.get("product_name") or tech.get("name")) or "Unnamed technology"
        version = _plain(tech.get("version") or tech.get("lookup_version"))
        for cve in tech["cves"]:
            if not isinstance(cve, Mapping):
                continue
            cve_id = _plain(cve.get("cve_id"))
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            url = cve.get("url") if isinstance(cve.get("url"), str) else ""
            rule: dict[str, Any] = {
                "id": cve_id,
                "name": cve_id,
                "shortDescription": {"text": cve_id},
                "fullDescription": {"text": _plain(cve.get("description"))},
                "properties": {"framework": "CVE"},
            }
            if url.lower().startswith("https://"):
                rule["helpUri"] = url
            rules.setdefault(cve_id, rule)
            target = f"{tech_name} {version}".strip()
            fingerprint = hashlib.sha256(f"{cve_id}|{target}".encode()).hexdigest()[:32]
            properties: dict[str, Any] = {"technology": tech_name, "version": version}
            for key, prop in (
                ("severity", "severity"),
                ("cvss_score", "cvssScore"),
                ("known_exploited", "knownExploited"),
                ("epss", "epss"),
            ):
                if cve.get(key) is not None:
                    value = cve[key]
                    properties[prop] = _plain(value) if isinstance(value, str) else value
            results.append(
                {
                    "ruleId": cve_id,
                    "level": _cve_level(cve),
                    "message": {"text": f"{cve_id} affects {target}."},
                    "fingerprints": {"aegisshield/v1": fingerprint},
                    "properties": properties,
                }
            )
    return results


_ATLAS_TAXONOMY = "MITRE ATLAS"


def _atlas_taxonomy(atlas: Mapping[str, Any], techniques: Any) -> dict[str, Any]:
    """A SARIF taxonomy of the ATLAS techniques the results point to (SARIF 2.1.0 ``taxa``)."""
    taxa: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        taxa.setdefault(tech["id"], {"id": tech["id"], "name": tech["name"],
                                     "shortDescription": {"text": tech["name"]}, "helpUri": tech["url"],
                                     "properties": {"tactic": tech["tactic"]}})
    return {"name": _ATLAS_TAXONOMY, "version": str(atlas.get("atlas_version") or "unknown"),
            "informationUri": "https://atlas.mitre.org/", "organization": "MITRE",
            "taxa": list(taxa.values())}


def to_sarif(
    result: Mapping[str, Any],
    app_profile: Mapping[str, Any] | None = None,
    app_description: str = "",
    *,
    nist_csf: Mapping[str, Any] | None = None,
    vuln_lookup: Mapping[str, Any] | None = None,
    tool_version: str = __version__,
) -> dict[str, Any]:
    """A SARIF 2.1.0 document of the threat model.

    Each STRIDE threat becomes a result whose rule is its mapped ATT&CK or
    ATLAS technique. The DREAD risk score, joined by threat ID, sets the
    level. Fingerprints are stable across runs so a re-run does not re-open
    triaged findings. With a NIST CSF mapping each threat result lists its
    categories; with a vulnerability lookup each CVE becomes a result too.
    ``app_description`` is not included (SARIF has no place for free text
    about the target); it is accepted so every exporter has one signature.
    """
    del app_description
    mitre_data = result.get("mitre_data") if isinstance(result.get("mitre_data"), list) else []
    threats = _threats(result)
    rule_list, rule_for_threat = _build_rules(mitre_data)
    rules = {rule["id"]: rule for rule in rule_list}
    dread_scores = _dread_scores(result)
    csf = _csf_by_threat(nist_csf)

    atlas = atlas_mapping_export(result.get(ATLAS_RESULT_KEY))
    atlas_by_threat = {row["threat_id"]: row["technique"] for row in (atlas or {}).get("threats", [])
                       if row.get("technique")}
    results: list[dict[str, Any]] = []
    for tid, threat in zip(assign_missing_ids(threats), threats, strict=True):
        fingerprint = _stable_fingerprint(threat)
        rule_id = rule_for_threat.get(fingerprint) or "AEGIS.UNKNOWN"
        score = dread_scores.get(tid)
        properties: dict[str, Any] = {
            "threatId": tid,
            "stride": _plain(threat.get("Threat Type")) or "Unknown",
            "potentialImpact": _plain(threat.get("Potential Impact")),
        }
        if score is not None:
            properties["dreadScore"] = round(score, 2)
        if csf.get(tid):
            properties["nistCsf"] = csf[tid]
        entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _dread_to_level(score),
            "message": {"text": _result_message(threat)},
            "fingerprints": {"aegisshield/v1": fingerprint},
            "properties": properties,
        }
        if tid in atlas_by_threat:
            entry["taxa"] = [{"id": atlas_by_threat[tid]["id"], "toolComponent": {"name": _ATLAS_TAXONOMY}}]
        results.append(entry)
    if "AEGIS.UNKNOWN" in {r["ruleId"] for r in results}:
        rules.setdefault(
            "AEGIS.UNKNOWN",
            {
                "id": "AEGIS.UNKNOWN",
                "name": "Unmapped threat",
                "shortDescription": {"text": "Threat with no technique mapping data."},
                "properties": {"framework": "STRIDE"},
            },
        )
    results.extend(_cve_results(vuln_lookup, rules))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "version": tool_version,
                "informationUri": _TOOL_INFO_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        ],
    }
    if atlas_by_threat:
        run["taxonomies"] = [_atlas_taxonomy(atlas or {}, atlas_by_threat.values())]
    profile = app_profile or {}
    if profile.get("app_type") or profile.get("industry_sector"):
        run["properties"] = {
            "appType": _plain(profile.get("app_type")),
            "industrySector": _plain(profile.get("industry_sector")),
        }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
