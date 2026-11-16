"""The PDF threat modeling report, rendered with markdown2 and xhtml2pdf.

``build_report_html`` builds the XHTML the PDF is drawn from (kept separate
so the escaping can be tested on text, not compressed PDF streams), and
``generate_pdf_bytes`` turns it into PDF bytes.

Every visitor and model string is escaped before it becomes markup, and the
renderer may load only embedded ``data:`` URIs (the logo): its resource
policy refuses every network fetch and local file read, so an image or link
in model output cannot read a file or reach the network. Markdown images are
also reduced to their alt text before rendering.

The cover has no industry badge: the header is the same for every industry.
"""

from __future__ import annotations

import base64
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisshield.core.errors import AegisError
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY
from aegisshield.pipeline.formatting_service import atlas_mapping_to_markdown
from aegisshield.safeguards import summary as safeguards_summary
from aegisshield.services.export_service import (
    csf_section_html,
    escape,
    markdown_html,
    profile_html,
    suggestions_html,
    threat_table_html,
    vuln_section_html,
)
from aegisshield.services.pdf_render import PdfRenderError, html_to_pdf, pdf_message

logger = logging.getLogger(__name__)

# The logo for light backgrounds (navy artwork): documents are on white paper.
LOGO_PATH = Path(__file__).resolve().parents[1] / "ui" / "assets" / "brand" / "logo-light.png"
_PDF_ERROR = "The PDF report could not be generated."

_GHERKIN_KEYWORDS = (
    "Feature",
    "Background",
    "Scenario Outline",
    "Scenario",
    "Examples",
    "Given",
    "When",
    "Then",
    "And",
    "But",
)
_GHERKIN_LINE_RE = re.compile(
    r"^(\s*)(" + "|".join(re.escape(k) for k in _GHERKIN_KEYWORDS) + r")\b(.*)$"
)
_FENCE_RE = re.compile(r"```(?:gherkin)?[ \t]*\n?(.*?)```", re.DOTALL | re.IGNORECASE)
_MERMAID_NODE_RE = re.compile(
    r"""
    \b([A-Za-z0-9_]+)                   # id
    \s*
    (?:
      \[\s*"?([^\]\n]+?)"?\s*\]          # [label]
      | \(\s*"?([^\)\n]+?)"?\s*\)        # (label)
      | \{\s*"?([^\}\n]+?)"?\s*\}        # {label}
    )
    """,
    flags=re.VERBOSE,
)
# One "source[label]? -->|label|? target[label]?" edge on a line.
_MERMAID_EDGE_LINE_RE = re.compile(
    r"""
    ^\s*
    ([A-Za-z0-9_]+)                     # source id
    (?:\s*(?:\[[^\]\n]+\]|\([^\)\n]+\)|\{[^\}\n]+\}))?  # optional source label
    \s*-[-.=]*>?\s*                     # arrow
    (?:\|[^|\n]*\|\s*)?                 # optional edge label
    ([A-Za-z0-9_&,\s]+?)                # target id(s)
    (?:\s*(?:\[[^\]\n]+\]|\([^\)\n]+\)|\{[^\}\n]+\}))?  # optional target label
    \s*;?\s*$
    """,
    flags=re.VERBOSE | re.MULTILINE,
)
# The two patterns above cost up to the square of one line's length, so they
# run one line at a time and skip a line longer than any real Mermaid line
# (a model's attack tree lines are under 300 characters).
MAX_MERMAID_LINE_CHARS = 2_000
# Levels of the tree drawn; deeper steps are summarized in one line, so an
# imported tree thousands of levels deep cannot exhaust the stack.
MAX_TREE_DEPTH = 40
_MERMAID_KEYWORDS = frozenset(
    {"graph", "flowchart", "subgraph", "end", "classdef", "class", "style", "direction"}
)

_PDF_STYLE = """
    @page { size: letter; margin: 0.6in 0.55in; }
    body { font-family: Helvetica, Arial, sans-serif; font-size: 10.5px; color: #1f2937; line-height: 1.45; }
    h1 { color: #0c4a6e; font-size: 22px; margin: 6px 0 4px; }
    h2 { color: #0c4a6e; font-size: 14px; margin: 14px 0 6px; padding-bottom: 3px; border-bottom: 1px solid #bdd7ee; }
    h3 { color: #0c4a6e; font-size: 12px; margin: 10px 0 4px; }
    h4 { color: #334155; font-size: 11px; margin: 8px 0 3px; }
    p { margin: 4px 0; }
    ul, ol { margin: 4px 0 4px 18px; padding: 0; }
    li { margin: 2px 0; }
    table { width: 100%; margin: 8px 0 12px; }
    th, td { border: 1px solid #cbd5e1; padding: 5px 6px; vertical-align: top; font-size: 10px; }
    th { background: #e0f2fe; color: #0c4a6e; text-align: left; font-weight: 600; font-size: 9.5px;
         text-transform: uppercase; letter-spacing: 0.3px; }
    tr { page-break-inside: avoid; }
    td.tid { font-family: "Courier New", monospace; font-weight: 700; color: #0c4a6e; white-space: nowrap; font-size: 9.5px; }
    table.threat-table th:nth-child(1), table.threat-table td:nth-child(1) { width: 9%; }
    table.threat-table th:nth-child(2), table.threat-table td:nth-child(2) { width: 12%; }
    .id-table table { width: 100%; }
    .id-table table th:first-child, .id-table table td:first-child {
      width: 62px; font-family: "Courier New", monospace; font-weight: 700; color: #0c4a6e;
      white-space: nowrap; text-align: left; }
    .id-table.dread table th, .id-table.dread table td { text-align: center; }
    .id-table.dread table th:first-child, .id-table.dread table td:first-child { text-align: left; }
    .id-table.dread table th:nth-child(n+2), .id-table.dread table td:nth-child(n+2) { width: 13%; }
    .id-table td, .id-table th { word-wrap: break-word; }
    pre.code-block { white-space: pre-wrap; word-break: break-word; background: #f8fafc;
      border: 1px solid #e2e8f0; border-left: 3px solid #0c4a6e; padding: 8px 10px;
      font-family: "Courier New", monospace; font-size: 9.5px; margin: 6px 0 10px; }
    .muted { color: #64748b; font-style: italic; }
    .meta { color: #475569; font-size: 10px; }
    .cover { border: 1px solid #cbd5e1; border-left: 4px solid #0c4a6e; background: #f8fafc;
      padding: 10px 14px; margin: 10px 0 18px; }
    .cover-title { color: #0c4a6e; font-size: 18px; font-weight: 700; margin: 0 0 4px; }
    .cover-meta { color: #475569; font-size: 10px; }
    .cover-meta span { margin-right: 10px; }
    .kv { width: 100%; margin: 6px 0 10px; }
    .kv td { border: none; padding: 2px 4px; font-size: 10px; }
    .kv .k { color: #475569; width: 28%; font-weight: 600; }
    .kv .v { color: #1f2937; }
    ul.tree-list { list-style: none; margin: 0 0 0 12px; padding: 0; }
    ul.tree-root-list { margin-left: 0; }
    li.tree-node { margin: 2px 0; padding-left: 10px; border-left: 1px dotted #94a3b8; font-size: 10.5px; }
    li.tree-root { border-left: 3px solid #0c4a6e; padding-left: 10px; margin-top: 4px; font-weight: 600; }
    li.tree-leaf .tree-label { color: #334155; }
    li.tree-ref { color: #64748b; font-style: italic; }
    .tree-label { color: #1f2937; }
    .tree-hint { color: #94a3b8; font-size: 9px; }
    .gherkin-block { background: #fafaf9; border: 1px solid #e7e5e4; border-left: 3px solid #059669;
      padding: 10px 12px; margin: 6px 0 10px; font-family: "Courier New", monospace; font-size: 10px;
      line-height: 1.55; color: #1c1917; }
    .gherkin-kw { font-weight: 700; color: #0c4a6e; padding-right: 4px; }
    .gherkin-feature, .gherkin-scenario, .gherkin-scenario-outline, .gherkin-background,
    .gherkin-examples { color: #7c2d12; }
    .gherkin-given { color: #0369a1; }
    .gherkin-when { color: #7e22ce; }
    .gherkin-then { color: #059669; }
    .gherkin-and, .gherkin-but { color: #64748b; }
    .gherkin-rest { color: #1c1917; font-weight: normal; }
    .tech { margin-top: 8px; }
    .section { margin-top: 10px; }
"""


def _logo_base64(path: Path = LOGO_PATH) -> str:
    """The logo as base64, or "" when the file cannot be read (the report still renders)."""
    try:
        return base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        logger.warning("report logo not readable at %s; rendering without it", path)
        return ""


def _parse_mermaid_graph(code: str) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
    """Return ``(labels, children, roots)`` for a Mermaid flowchart."""
    lines = [line for line in code.split("\n") if len(line) <= MAX_MERMAID_LINE_CHARS]
    labels: dict[str, str] = {}
    for line in lines:
        for match in _MERMAID_NODE_RE.finditer(line):
            node_id = match.group(1)
            label = (match.group(2) or match.group(3) or match.group(4) or "").strip().strip('"')
            if label:
                labels.setdefault(node_id, label)

    children: dict[str, list[str]] = {}
    targets_of_any: set[str] = set()
    all_nodes: set[str] = set(labels)
    for line in lines:
        match = _MERMAID_EDGE_LINE_RE.match(line)
        if match is None:
            continue
        source_id = match.group(1)
        if source_id.lower() in _MERMAID_KEYWORDS:
            continue
        # "A & B" and "A, B" style multi-target edges.
        target_ids = [t.strip() for t in re.split(r"[,&]", match.group(2) or "") if t.strip()]
        if not target_ids:
            continue
        all_nodes.add(source_id)
        for target_id in target_ids:
            all_nodes.add(target_id)
            children.setdefault(source_id, []).append(target_id)
            targets_of_any.add(target_id)

    for node_id in all_nodes:
        labels.setdefault(node_id, node_id)

    # Roots: nodes with children that are never the target of another edge.
    roots = [n for n in children if n not in targets_of_any] or list(children)
    appearance = {n: code.find(n) for n in roots}
    roots.sort(key=lambda n: appearance[n] if appearance[n] >= 0 else 1 << 30)
    return labels, children, roots


def render_attack_tree(code: str) -> str:
    """The Mermaid attack tree as an indented text outline (labels escaped).

    The PDF cannot draw Mermaid, so the tree is shown as text: an outline when
    the edges parse, otherwise the escaped Mermaid source in a ``<pre>``.
    """
    if not code.strip():
        return '<p class="muted">No attack tree generated.</p>'
    labels, children, roots = _parse_mermaid_graph(code)
    if not children:
        return f'<pre class="code-block">{escape(code)}</pre>'

    visited: set[str] = set()

    def walk(node_id: str, depth: int, buf: list[str]) -> None:
        label = escape(labels.get(node_id, node_id))
        if node_id in visited:
            # A cycle or shared child: show a reference line, do not recurse.
            buf.append(
                f'<li class="tree-node tree-ref"><span class="tree-label">{label}</span>'
                '<span class="tree-hint"> (see above)</span></li>'
            )
            return
        visited.add(node_id)
        kids = children.get(node_id, [])
        if kids and depth + 1 >= MAX_TREE_DEPTH:
            buf.append(f'<li class="tree-node"><span class="tree-label">{label}</span>'
                       f'<span class="tree-hint"> (steps below level {MAX_TREE_DEPTH} not shown)</span></li>')
            return
        classes = "tree-node" + (" tree-root" if depth == 0 else "") + ("" if kids else " tree-leaf")
        buf.append(f'<li class="{classes}"><span class="tree-label">{label}</span>')
        if kids:
            buf.append('<ul class="tree-list">')
            for kid in kids:
                walk(kid, depth + 1, buf)
            buf.append("</ul>")
        buf.append("</li>")

    parts = ['<ul class="tree-list tree-root-list">']
    for root in roots:
        walk(root, 0, parts)
    parts.append("</ul>")
    return "".join(parts)


def _highlight_gherkin_block(code: str) -> str:
    """A block of Gherkin as styled, escaped HTML (indentation kept)."""
    html_lines: list[str] = []
    for raw_line in code.splitlines() or [""]:
        match = _GHERKIN_LINE_RE.match(raw_line)
        if not match:
            html_lines.append(escape(raw_line).replace(" ", "&nbsp;"))
            continue
        indent = match.group(1).replace(" ", "&nbsp;")
        keyword = match.group(2)
        rest = escape(match.group(3)).replace(" ", "&nbsp;")
        slug = keyword.lower().replace(" ", "-")
        html_lines.append(
            f'{indent}<span class="gherkin-kw gherkin-{slug}">{keyword}</span>'
            f'<span class="gherkin-rest">{rest}</span>'
        )
    return f'<div class="gherkin-block">{"<br/>".join(html_lines)}</div>'


def render_test_cases(markdown_text: str) -> str:
    """Test cases: fenced Gherkin blocks highlighted, the prose between them as markdown."""
    if not markdown_text.strip():
        return ""
    parts: list[str] = []
    last_end = 0
    for match in _FENCE_RE.finditer(markdown_text):
        prose = markdown_text[last_end : match.start()].strip()
        if prose:
            parts.append(markdown_html(prose))
        code_body = match.group(1).rstrip()
        if code_body:
            parts.append(_highlight_gherkin_block(code_body))
        last_end = match.end()
    trailing = markdown_text[last_end:].strip()
    if trailing:
        parts.append(markdown_html(trailing))
    return "".join(parts)


def _section(title: str, body_html: str, *, break_before: bool = False) -> str:
    """A titled section, or "" when the body is empty (skipped add-ons leave no header)."""
    if not body_html.strip():
        return ""
    page_break = ' style="page-break-before: always;"' if break_before else ""
    return f'<div class="section"{page_break}><h2>{escape(title)}</h2>{body_html}</div>'


def _text(result: Mapping[str, Any], key: str) -> str:
    value = result.get(key)
    return value if isinstance(value, str) else ""


def _atlas_section(result: Mapping[str, Any]) -> list[str]:
    """The "MITRE ATLAS" section for an AI system; nothing for any other result."""
    block = atlas_mapping_to_markdown(result.get(ATLAS_RESULT_KEY))
    return [_section("MITRE ATLAS", markdown_html(block))] if block else []


def build_report_html(
    result: Mapping[str, Any],
    app_profile: Mapping[str, Any] | None,
    app_description: str,
    *,
    nist_csf: Mapping[str, Any] | None = None,
    vuln_lookup: Mapping[str, Any] | None = None,
    logo_base64: str | None = None,
) -> str:
    """The XHTML the PDF report is drawn from.

    ``logo_base64`` defaults to the packaged logo; pass "" to omit it.
    """
    profile = app_profile or {}
    logo = _logo_base64() if logo_base64 is None else logo_base64
    logo_html = f'<img src="data:image/png;base64,{logo}" width="120" />' if logo else ""
    threats = result.get("threat_model")
    threats = [t for t in threats if isinstance(t, dict)] if isinstance(threats, list) else []
    raw_suggestions = result.get("improvement_suggestions")
    suggestions = (
        [str(s) for s in raw_suggestions if s not in (None, "")]
        if isinstance(raw_suggestions, list)
        else []
    )
    mitigations = markdown_html(_text(result, "mitigations_markdown"))
    dread = markdown_html(_text(result, "dread_assessment_markdown"))
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    meta = "".join(
        f"<span><strong>{label}:</strong> {escape(value)}</span>"
        for label, value in (
            ("Generated", generated),
            ("Application", profile.get("app_type") or "N/A"),
            ("Industry", profile.get("industry_sector") or "N/A"),
        )
    )
    body = [
        f'<div class="cover">{logo_html}<h1 class="cover-title">Threat Modeling Report</h1>'
        f'<div class="cover-meta">{meta}</div></div>',
        _section("Application Profile", profile_html(profile, app_description)),
        _section("Safeguards", safeguards_summary.as_html(result.get("safeguards"),
                                                          result.get("review_flags"))),
        _section("Improvement Suggestions", suggestions_html(suggestions)),
        _section("Threat Model", threat_table_html(threats), break_before=True),
        _section("Attack Tree", render_attack_tree(_text(result, "attack_tree_code"))),
        _section(
            "MITRE ATT&CK", markdown_html(_text(result, "mitre_attack_markdown")), break_before=True
        ),
        *_atlas_section(result),
        _section("NVD CVE Findings", markdown_html(_text(result, "nvd_vulnerabilities_markdown"))),
        _section("AlienVault OTX Intelligence", markdown_html(_text(result, "otx_data_markdown"))),
        _section(
            "Mitigations",
            f'<div class="id-table mitigations">{mitigations}</div>' if mitigations else "",
            break_before=True,
        ),
        _section(
            "DREAD Risk Assessment", f'<div class="id-table dread">{dread}</div>' if dread else ""
        ),
        _section("Security Test Cases", render_test_cases(_text(result, "test_cases_markdown"))),
        _section("NIST CSF 2.0 Mapping", csf_section_html(nist_csf), break_before=True),
        _section("Vulnerability Lookup", vuln_section_html(vuln_lookup), break_before=True),
    ]
    return (
        '<html><head><meta charset="utf-8" />'
        f"<style>{_PDF_STYLE}</style></head><body>"
        + "".join(body)
        + "</body></html>"
    )


def render_pdf(html_content: str) -> bytes:
    """Draw ``html_content`` as PDF bytes, loading nothing but embedded ``data:`` URIs.

    Uses ``pdf_render.html_to_pdf``, whose resource policy refuses every
    network fetch and every local file read, so an image or stylesheet
    reference in model output cannot reach a host or read a file. Raises
    ``AegisError`` with a plain message when the PDF is refused or xhtml2pdf
    fails: the renderer's own sentence when it names a reason (busy, a table
    too long), otherwise a fixed one.
    """
    try:
        return html_to_pdf(html_content)
    except PdfRenderError as exc:
        raise AegisError(pdf_message(exc, _PDF_ERROR)) from exc


def generate_pdf_bytes(
    result: Mapping[str, Any],
    app_profile: Mapping[str, Any] | None,
    app_description: str,
    *,
    nist_csf: Mapping[str, Any] | None = None,
    vuln_lookup: Mapping[str, Any] | None = None,
) -> bytes:
    """The threat modeling report as PDF bytes (see ``render_pdf`` for errors)."""
    return render_pdf(
        build_report_html(
            result, app_profile, app_description, nist_csf=nist_csf, vuln_lookup=vuln_lookup
        )
    )
