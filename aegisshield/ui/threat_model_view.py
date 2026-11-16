"""The results of one threat model, shared by the wizard and the detail page.

Layout: tiles, the STRIDE breakdown, detected patterns, then tabs for each
artifact, and the improvement suggestions. Model output is placed only through
``kit.model_markdown``, escaped HTML, or data tables; never as raw HTML.
"""

from __future__ import annotations

import html
import json
import logging
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import streamlit as st

from aegisshield.pipeline.ai_system import payload_is_ai_system
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY, STATUS_TEXT
from aegisshield.pipeline.formatting_service import atlas_mapping_export, atlas_mapping_to_markdown
from aegisshield.safeguards import summary as safeguards_summary
from aegisshield.services import (
    export_service,
    nist_csf_service,
    regulation_service,
    report_service,
)
from aegisshield.services.posture_service import severity_for_score
from aegisshield.storage import Record, RecordKind
from aegisshield.ui import kit, routes, safeguards_view, state, tm_detail
from aegisshield.ui.theme import Tone

__all__ = [
    "STRIDE_ORDER",
    "atlas_rows",
    "bundle_markdown",
    "count_atlas_techniques",
    "count_cves",
    "count_otx_reports",
    "count_techniques",
    "count_tree_links",
    "Export",
    "csf_for",
    "exports",
    "gherkin_text",
    "is_ai_system",
    "markdown_table",
    "pattern_source_label",
    "render_exports",
    "render_results",
    "render_workflow_scans",
    "stride_counts",
]

logger = logging.getLogger(__name__)

STRIDE_ORDER = ("Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                "Denial of Service", "Elevation of Privilege")
_PATTERN_SOURCES = {
    "user": "you chose them",
    "regex": "detected from the description",
    "llm": "detected by the model",
    "regex+llm": "none matched",
    "none": "none",
}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_SEVERITY_TONES = {"critical": Tone.CRIT, "high": Tone.CRIT, "medium": Tone.WARN, "low": Tone.OK}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


# ------------------------------------------------------------- counting


def _threats(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    threats = payload.get("threat_model")
    return [t for t in threats if isinstance(t, dict)] if isinstance(threats, list) else []


def count_techniques(payload: Mapping[str, Any]) -> int:
    """Mapped ATT&CK techniques across every threat."""
    total = 0
    for entry in payload.get("mitre_data") or []:
        if isinstance(entry, dict) and isinstance(entry.get("mitre_techniques"), list):
            total += len(entry["mitre_techniques"])
    return total


def count_cves(payload: Mapping[str, Any]) -> int:
    """Distinct CVE ids in the NVD text."""
    return len(set(_CVE.findall(str(payload.get("nvd_vulnerabilities_markdown") or ""))))


def count_otx_reports(payload: Mapping[str, Any]) -> int:
    """OTX reports in the threat-intel text (paragraphs), 0 when blank."""
    text = str(payload.get("otx_data_markdown") or "").strip()
    return len([chunk for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]) if text else 0


def count_tree_links(payload: Mapping[str, Any]) -> int:
    """Links in the Mermaid attack tree."""
    return str(payload.get("attack_tree_code") or "").count("-->")


def stride_counts(threats: Sequence[Mapping[str, Any]]) -> list[tuple[str, int]]:
    """Threats per STRIDE category: the six in order, then any other type."""
    counts = Counter(str(t.get("Threat Type") or "Other") for t in threats)
    ordered = [(name, counts.pop(name)) for name in STRIDE_ORDER if counts.get(name)]
    return ordered + sorted(counts.items())


def pattern_source_label(source: object) -> str:
    """How the detected patterns were found, in words."""
    key = str(source or "none")
    return _PATTERN_SOURCES.get(key, key)


def is_ai_system(payload: Mapping[str, Any]) -> bool:
    """True when the EU AI Act view applies: an AI system
    (``ai_system.payload_is_ai_system``), or the EU AI Act among its frameworks."""
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    return payload_is_ai_system(payload) or "EU AI Act" in (profile.get("compliance_requirements") or [])


def atlas_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The ATLAS block's rows (catalog names and links), or none for a result
    without an ATLAS mapping (any other system, or an older record)."""
    block = atlas_mapping_export(payload.get(ATLAS_RESULT_KEY))
    return block["threats"] if block else []


def count_atlas_techniques(payload: Mapping[str, Any]) -> int:
    """Threats with a mapped ATLAS technique."""
    return sum(1 for row in atlas_rows(payload) if row.get("technique"))


def markdown_table(text: object) -> list[dict[str, str]] | None:
    """The first markdown table in ``text`` as rows, or None if there is none."""
    if not isinstance(text, str):
        return None
    header: list[str] | None = None
    rows: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            if header is not None and rows:
                break
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if all(re.fullmatch(r":?-+:?", c.replace(" ", "")) for c in cells if c):
            continue
        rows.append({name: cells[i] if i < len(cells) else "" for i, name in enumerate(header)})
    return rows or None


_SPACE_RUN = re.compile(r"\s*")


def gherkin_text(markdown: object) -> str:
    """Every gherkin block in the test cases, as one ``.feature`` file.

    A block opens with three backticks, an optional ``gherkin`` or
    ``cucumber`` tag, and whitespace holding a line break; it runs to the
    next three backticks. Found with ``str.find``, so a hostile text costs
    time in step with its length.
    """
    if not isinstance(markdown, str):
        return ""
    blocks: list[str] = []
    index = 0
    while (start := markdown.find("```", index)) != -1:
        body = start + 3
        for tag in ("gherkin", "cucumber"):
            if markdown.startswith(tag, body):
                body += len(tag)
                break
        space_end = _SPACE_RUN.match(markdown, body).end()  # type: ignore[union-attr]
        newline = markdown.rfind("\n", body, space_end)
        if newline == -1:
            index = start + 1
            continue
        end = markdown.find("```", newline + 1)
        if end == -1:
            break
        blocks.append(markdown[newline + 1 : end])
        index = end + 3
    return "\n\n".join(block.strip() for block in blocks if block.strip()) + ("\n" if blocks else "")


def bundle_markdown(record: Record) -> str:
    """The whole threat model as one Markdown file."""
    payload = record.payload
    parts = [f"# {record.title}", "", "## Description", "", str(payload.get("description") or ""),
             "", "## Threat model", "", str(payload.get("threat_model_markdown") or "")]
    sections = (
        ("Improvement suggestions", "improvement_suggestions_markdown"),
        ("MITRE ATT&CK mapping", "mitre_attack_markdown"),
        ("MITRE ATLAS", ATLAS_RESULT_KEY),
        ("NVD vulnerabilities", "nvd_vulnerabilities_markdown"),
        ("AlienVault OTX", "otx_data_markdown"),
        ("Mitigations", "mitigations_markdown"),
        ("DREAD assessment", "dread_assessment_markdown"),
        ("Test cases", "test_cases_markdown"),
    )
    for title, key in sections:
        if key == ATLAS_RESULT_KEY:
            text = atlas_mapping_to_markdown(payload.get(key)).strip()
        else:
            text = str(payload.get(key) or "").strip()
        if text:
            parts += ["", f"## {title}", "", text]
    code = str(payload.get("attack_tree_code") or "").strip()
    if code:
        parts += ["", "## Attack tree", "", "```mermaid", code, "```"]
    parts += ["", safeguards_summary.as_markdown(payload.get("safeguards"), payload.get("review_flags"))]
    return "\n".join(parts).strip() + "\n"


def csf_for(record: Record) -> dict[str, Any]:
    """The NIST CSF report for a record, computed once per record and session."""
    payload = record.payload
    return state.session_memo("csf", record.id, lambda: nist_csf_service.csf_report(
        _threats(payload), payload.get("mitre_data") if isinstance(payload.get("mitre_data"), list) else None))


# --------------------------------------------------------------- results


def render_results(record: Record, *, duration: float | None = None, key_prefix: str = "tm") -> None:
    """Everything the run produced, in display order."""
    payload = record.payload
    threats = _threats(payload)
    _, dread_by_id = tm_detail.parse_dread_table(payload.get("dread_assessment_markdown"))
    _summary(payload, threats, duration)
    kit.answered_by(payload.get("model"))
    safeguards_view.render_safeguards(payload.get("safeguards"), key=key_prefix)
    safeguards_view.render_review_flags(
        payload.get("review_flags"), key=key_prefix,
        threat_titles={str(t.get("ID")): str(t.get("Scenario") or t.get("Threat Type") or "")
                       for t in threats if t.get("ID")})
    _agentic_blocks(payload)
    render_workflow_scans(record, key_prefix=key_prefix)

    mitre_tab = "MITRE ATT&CK and ATLAS" if atlas_rows(payload) else "MITRE ATT&CK mapping"
    tabs = ["Attack path", "STRIDE findings", mitre_tab]
    if dread_by_id:
        tabs.append("DREAD")
    if str(payload.get("mitigations_markdown") or "").strip():
        tabs.append("Mitigations")
    if str(payload.get("test_cases_markdown") or "").strip():
        tabs.append("Test cases")
    tabs += ["Compliance mapping", "Lookup results"]
    containers = dict(zip(tabs, st.tabs(tabs, key=f"{key_prefix}_tabs"), strict=True))
    with containers["Attack path"]:
        _attack_path(payload, threats, dread_by_id)
    with containers["STRIDE findings"]:
        _findings(payload, threats, dread_by_id)
    with containers[mitre_tab]:
        _mitre(payload)
        _atlas(payload)
    if "DREAD" in containers:
        with containers["DREAD"]:
            _dread(payload, dread_by_id)
    if "Mitigations" in containers:
        with containers["Mitigations"]:
            _table_or_markdown(payload.get("mitigations_markdown"), "mitigations", top=True)
    if "Test cases" in containers:
        with containers["Test cases"]:
            kit.model_markdown(str(payload.get("test_cases_markdown") or ""))
    with containers["Compliance mapping"]:
        _compliance(record)
    with containers["Lookup results"]:
        _lookups(payload)
    _suggestions(payload)


_SCAN_STATUS_WORDS = {"complete": "Complete", "incomplete": "Incomplete, no result",
                      "failed": "Failed, no result"}
_MAX_LISTED_SCANS = 20
# Streamlit shows its own fixed text when a download cannot be built, so the
# reasons a PDF can be refused are said here, before the click.
PDF_FAILED_HINT = ("If the PDF download fails, the server is busy or a table is too long "
                   "for a PDF: try again in a minute, or download the HTML report.")


def render_workflow_scans(record: Record, *, key_prefix: str = "tm") -> None:
    """The AI workflow scans attached to this threat model, and, for an AI
    system where scans are offered, a link that opens the scan page for it.

    The scan page attaches a finished scan it was opened for
    (``pages.ai_scan.attach_scan``); the ids live in the payload's
    ``ai_scans`` list, and each is looked up in this session's workspace.
    """
    payload = record.payload
    ids = [i for i in (payload.get("ai_scans") if isinstance(payload.get("ai_scans"), list) else [])
           if isinstance(i, str)][-_MAX_LISTED_SCANS:]
    offered = is_ai_system(payload) and routes.ai_scan_available()
    if not ids and not offered:
        return
    with kit.card(f"{key_prefix}_workflow_scans"):
        kit.section("AI workflow scans", "garak scans of your own AI workflow attached to this threat model. "
                    "A scan tests a system prompt and model through this app's client, not the deployed system.")
        workspace = state.get_workspace()
        for scan_id in reversed(ids):
            scan = workspace.get(RecordKind.AI_SCANS, scan_id)
            if scan is None:
                st.html('<p class="tx-muted">A scan that is no longer in this session.</p>')
                continue
            status = scan.payload.get("status")
            words = _SCAN_STATUS_WORDS.get(status if isinstance(status, str) else "", "Unknown")
            model = scan.payload.get("settings", {}).get("model") if isinstance(scan.payload.get("settings"),
                                                                                  dict) else None
            simulated = ", simulated model" if isinstance(model, dict) and model.get("kind") == "simulated" else ""
            st.html(f'<p class="tx-name">{_esc(scan.title)} &middot; {_esc(words)}{_esc(simulated)}</p>')
            if routes.ai_scan_available():
                kit.record_link("ai_scan", scan.id, "Open scan")
        if offered:
            st.page_link(routes.page("ai_scan"), label="Test this workflow with garak",
                         icon=":material/play_arrow:", query_params={"model": record.id})


def _summary(payload: Mapping[str, Any], threats: list[dict[str, Any]], duration: float | None) -> None:
    tiles = [
        kit.Tile("Threats", len(threats), "STRIDE scenarios", Tone.ACCENT),
        kit.Tile("MITRE techniques", count_techniques(payload), "Mapped ATT&CK techniques"),
        *([kit.Tile("ATLAS techniques", count_atlas_techniques(payload), "Mapped ATLAS techniques")]
          if atlas_rows(payload) else []),
        kit.Tile("NVD CVEs", count_cves(payload), "Version-aware lookups"),
        kit.Tile("OTX reports", count_otx_reports(payload), "Threat intelligence"),
        kit.Tile("Attack tree links", count_tree_links(payload), "Edges in the tree"),
    ]
    if duration is not None:
        tiles.append(kit.Tile("Duration", f"{duration:.1f}s", "End to end"))
    kit.stat_row(tiles)
    counts = stride_counts(threats)
    if counts:
        chips = "".join(
            f'<span class="tm-chip"><span class="tm-letter">{_esc(tm_detail.stride_letter(name) or "?")}</span>'
            f"<strong>{_esc(name)}</strong> {count}</span>"
            for name, count in counts)
        st.html(f'<div class="tm-label">STRIDE breakdown</div><div class="tm-chips">{chips}</div>')
    patterns = [str(p) for p in payload.get("detected_patterns") or []]
    if patterns:
        chips = "".join(f'<span class="tm-chip">{_esc(p)}</span>' for p in patterns)
        source = pattern_source_label(payload.get("pattern_source"))
        st.html(f'<div class="tm-label">Application patterns ({_esc(source)})</div>'
                f'<div class="tm-chips">{chips}</div>')


def _agentic_blocks(payload: Mapping[str, Any]) -> None:
    plan = payload.get("lead_plan")
    teammate = payload.get("teammate_review")
    rebuttal = payload.get("rebuttal_review")
    if not any(isinstance(v, dict) for v in (plan, teammate, rebuttal)):
        return
    with st.expander("Agent team: the lead's plan and the reviews", expanded=False):
        if isinstance(plan, dict):
            kit.section("Lead plan", f"Planned by: {plan.get('decider') or 'rule'}")
            kit.model_markdown(str(plan.get("rationale") or ""))
            rows = [{"Section": str(s.get("section") or ""), "Focus": str(s.get("focus") or ""),
                     "Skipped": "Yes" if s.get("skip") is True else "No"}
                    for s in plan.get("sections") or [] if isinstance(s, dict)]
            if rows:
                st.dataframe(rows, hide_index=True, width="stretch")
        if isinstance(teammate, dict):
            kit.section("Teammate review", "Possible false positives in the draft.")
            kit.model_markdown(str(teammate.get("notes") or ""))
            flags = [{"Threat": str(f.get("threat") or ""), "Reason": str(f.get("reason") or "")}
                     for f in teammate.get("flags") or [] if isinstance(f, dict)]
            if flags:
                st.dataframe(flags, hide_index=True, width="stretch")
        if isinstance(rebuttal, dict):
            kit.section("Rebuttal review", "The highest DREAD rows, tested against real scope.")
            rows = [{"Threat": str(r.get("threat") or ""),
                     "Counterexample": str(r.get("counterexample") or ""),
                     "Adjusted score": str(r.get("adjusted") or ""),
                     "Reason": str(r.get("reason") or "")}
                    for r in rebuttal.get("rebuttals") or [] if isinstance(r, dict)]
            if rows:
                st.dataframe(rows, hide_index=True, width="stretch")


def _attack_path(payload: Mapping[str, Any], threats: list[dict[str, Any]],
                 dread_by_id: Mapping[str, tm_detail.DreadRow]) -> None:
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    nodes, edges = tm_detail.derive_attack_chain(profile, threats, dread_by_id)
    kit.section("Attack path", "From the internet to the data at stake, through the two "
                "highest-risk threats.")
    if len(nodes) < 2:
        kit.notice("Not enough data to draw an attack path.", tone=Tone.NEUTRAL)
    else:
        image = tm_detail.svg_image(tm_detail.chain_svg(nodes, edges), "Attack path graph")
        st.html(f'<div class="tm-diagram">{image}</div>'
                '<div class="tm-legend"><span style="--dot: var(--info)">Entry point</span>'
                '<span style="--dot: var(--warn)">Application</span>'
                '<span style="--dot: var(--crit)">Critical node or attack step</span></div>')
    code = str(payload.get("attack_tree_code") or "")
    kit.section("Attack tree", "The model's attack tree, from the attacker's goal to each step.")
    svg = tm_detail.attack_tree_svg(code)
    if svg:
        st.html(f'<div class="tm-diagram">{tm_detail.svg_image(svg, "Attack tree")}</div>')
    elif code.strip():
        kit.notice("The attack tree could not be drawn; its source is below.", tone=Tone.WARN)
    else:
        kit.notice("No attack tree was generated.", tone=Tone.NEUTRAL)
    if code.strip():
        with st.expander("Mermaid source (copy it into any Mermaid editor)"):
            st.code(code, language="text")


def _first_technique(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in payload.get("mitre_data") or []:
        if not isinstance(entry, dict):
            continue
        threat = entry.get("threat") if isinstance(entry.get("threat"), dict) else {}
        techniques = [t for t in entry.get("mitre_techniques") or [] if isinstance(t, dict)]
        if threat.get("ID") and techniques:
            out.setdefault(str(threat["ID"]), techniques[0])
    return out


def _findings(payload: Mapping[str, Any], threats: list[dict[str, Any]],
              dread_by_id: Mapping[str, tm_detail.DreadRow]) -> None:
    if not threats:
        kit.notice("No STRIDE findings recorded.", tone=Tone.NEUTRAL)
        return
    techniques = _first_technique(payload)
    atlas = {str(row.get("threat_id")): row["technique"] for row in atlas_rows(payload) if row.get("technique")}
    flagged = {tid for tid, _, _ in safeguards_summary.flag_items(payload.get("review_flags")) if tid}

    def risk(t: Mapping[str, Any]) -> float:
        row = dread_by_id.get(str(t.get("ID") or ""))
        return row.risk if row else -1.0

    kit.section("STRIDE findings", f"{len(threats)} findings, highest risk first.")
    cards = []
    for threat in sorted(threats, key=risk, reverse=True):
        threat_id = str(threat.get("ID") or "")
        row = dread_by_id.get(threat_id)
        if row:
            level = severity_for_score(row.risk)
            tone = _SEVERITY_TONES.get(level, Tone.NEUTRAL)
            sev = (f'<div class="tm-sev ax-tone-{tone.value}">{row.risk:.1f}'
                   f"<small>{_esc(level)}</small></div>")
        else:
            sev = '<div class="tm-sev ax-tone-neutral">-<small>unscored</small></div>'
        title = threat.get("Scenario") or threat.get("Threat Type") or threat_id or "Threat"
        head = [f'<span class="tm-id">{_esc(threat_id)}</span>'] if threat_id else []
        head.append(f'<span class="tm-finding-title">{_esc(title)}</span>')
        head.append(kit.badge_html(str(threat.get("Threat Type") or "Other"), tone=Tone.ACCENT))
        if threat_id in flagged:
            head.append(kit.badge_html("Review flag", tone=Tone.WARN))
        technique = techniques.get(threat_id)
        if technique:
            tid = str(technique.get("technique_id") or "")
            url = tm_detail.mitre_url(tid)
            name = _esc(f"{tid} {technique.get('name') or ''}".strip())
            head.append(f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{name}</a>'
                        if url else f"<span>{name}</span>")
        atlas_technique = atlas.get(threat_id)
        if atlas_technique:
            head.append(_atlas_link(atlas_technique["id"], atlas_technique["name"], atlas_technique["url"]))
        impact = threat.get("Potential Impact")
        body = f"<p>{_esc(impact)}</p>" if impact else ""
        anchor = f' id="{safeguards_view.threat_anchor(threat_id)}"' if threat_id else ""
        cards.append(f'<div class="tm-finding"{anchor}>{sev}<div><div class="tm-finding-head">{"".join(head)}'
                     f"</div>{body}</div></div>")
    st.html(f'<div class="tm-findings">{"".join(cards)}</div>')
    with st.expander("As a table"):
        st.dataframe(
            [{"ID": str(t.get("ID") or ""), "Type": str(t.get("Threat Type") or ""),
              "Scenario": str(t.get("Scenario") or ""), "Impact": str(t.get("Potential Impact") or ""),
              "Risk": dread_by_id[str(t.get("ID"))].risk if str(t.get("ID")) in dread_by_id else None}
             for t in threats],
            hide_index=True, width="stretch")


def _mitre(payload: Mapping[str, Any]) -> None:
    rows = []
    for entry in payload.get("mitre_data") or []:
        if not isinstance(entry, dict):
            continue
        threat = entry.get("threat") if isinstance(entry.get("threat"), dict) else {}
        for tech in entry.get("mitre_techniques") or []:
            if not isinstance(tech, dict):
                continue
            tid = str(tech.get("technique_id") or "")
            rows.append({"Threat": str(threat.get("ID") or ""),
                         "STRIDE": str(threat.get("Threat Type") or ""),
                         "Technique": tid, "Name": str(tech.get("name") or ""),
                         "Tactic": str(tech.get("tactic") or ""),
                         "Framework": str(tech.get("framework") or ""),
                         "Link": tm_detail.mitre_url(tid)})
    if not rows:
        kit.notice("No techniques were mapped.", tone=Tone.NEUTRAL)
        return
    kit.section("MITRE ATT&CK mapping", "Each threat's technique, checked against the ATT&CK catalog.")
    st.dataframe(rows, hide_index=True, width="stretch", column_config={
        "Link": st.column_config.LinkColumn("MITRE page" if any(r["Framework"] == "ATLAS" for r in rows)
                                            else "ATT&CK page", display_text="Open"),
    })
    with st.expander("Technique descriptions"):
        kit.model_markdown(str(payload.get("mitre_attack_markdown") or ""))


def _atlas_link(technique_id: object, name: object, url: object) -> str:
    text = _esc(f"{technique_id} {name}".strip())
    return (f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">{text}</a>'
            if isinstance(url, str) and url.startswith("https://atlas.mitre.org/") else f"<span>{text}</span>")


def _atlas_links(items: object, total: object, source: object, technique_id: str) -> str:
    links = [_atlas_link(i.get("id"), i.get("name"), i.get("url")) for i in items or [] if isinstance(i, dict)]
    if not links:
        return '<span class="tm-muted">none in the ATLAS catalog for this technique</span>'
    note = f", listed for the parent technique {_esc(source)}" if source and source != technique_id else ""
    return f'{", ".join(links)} <span class="tm-muted">({len(links)} of {_esc(total)}{note})</span>'


def _atlas(payload: Mapping[str, Any]) -> None:
    """The MITRE ATLAS block: per threat its tactic, technique, mitigations, and
    case studies, all read from the bundled catalog and linked to atlas.mitre.org."""
    block = atlas_mapping_export(payload.get(ATLAS_RESULT_KEY))
    if not block:
        return
    kit.section("MITRE ATLAS", f"ATLAS {block['atlas_version']} technique for each threat, alongside its "
                f"ATT&CK {block['attack_version']} technique. Mitigations and case studies are the ones "
                "the ATLAS catalog links to the technique; the model did not write them.")
    if block["call"] == "failed":
        kit.notice("The ATLAS step did not finish, so no ATLAS technique was mapped.", tone=Tone.WARN)
    cards = []
    for row in block["threats"]:
        threat_id = str(row.get("threat_id") or "")
        head = [f'<span class="tm-id">{_esc(threat_id)}</span>'] if threat_id else []
        head.append(kit.badge_html(str(row.get("threat_type") or "Other"), tone=Tone.ACCENT))
        technique = row.get("technique")
        if technique:
            head.append(_atlas_link(technique["id"], technique["name"], technique["url"]))
            head.append(f'<span class="tm-chip">{_esc(technique["tactic"])}</span>')
            body = "".join(
                f"<p><strong>{label}:</strong> "
                f"{_atlas_links(row.get(key), row.get(f'{key}_total'), row.get(f'{key}_from'), technique['id'])}</p>"
                for label, key in (("Mitigations", "mitigations"), ("Case studies", "case_studies")))
        else:
            body = f'<p class="tm-muted">{_esc(STATUS_TEXT.get(str(row.get("status")), "No ATLAS technique."))}</p>'
        cards.append(f'<div class="tm-atlas-row"><div class="tm-finding-head">{"".join(head)}</div>{body}</div>')
    st.html(f'<div class="tm-atlas" data-testid="tm-atlas">{"".join(cards)}</div>')


def _dread(payload: Mapping[str, Any], dread_by_id: Mapping[str, tm_detail.DreadRow]) -> None:
    rows = sorted(dread_by_id.values(), key=lambda r: r.risk, reverse=True)
    top = tm_detail.top_threat_row(rows)
    left, right = st.columns([1, 2], gap="large")
    with left, kit.card("dread_top"):
        if top is not None:
            level = severity_for_score(top.risk)
            tone = _SEVERITY_TONES.get(level, Tone.NEUTRAL)
            bars = "".join(
                f'<div class="tm-bar"><span>{_esc(label)}</span><div class="tm-bar-track">'
                f'<div class="tm-bar-fill" style="width:{max(0.0, min(100.0, value * 10)):.0f}%"></div>'
                f'</div><span class="tm-bar-value">{value:g}</span></div>'
                for _key, label, value in tm_detail.top_threat_axes(top))
            st.html(f'<div class="ax-tone-{tone.value}"><div class="tm-label">Highest risk</div>'
                    f'<div class="tm-dread-top"><span class="tm-dread-score">{top.risk:.1f}</span>'
                    f'<span class="tm-id">{_esc(top.id)}</span>{kit.severity_badge_html(level)}</div>'
                    f'<div class="tm-bars">{bars}</div></div>')
            composite = tm_detail.dread_composite(rows)
            if composite is not None:
                st.caption(f"Average risk across {len(rows)} threats: {composite:.1f}")
    with right:
        st.dataframe(
            [{"ID": r.id, "Damage": r.damage, "Reproducibility": r.reproducibility,
              "Exploitability": r.exploitability, "Affected users": r.affected,
              "Discoverability": r.discoverability, "Risk": r.risk,
              "Severity": severity_for_score(r.risk).capitalize()} for r in rows],
            hide_index=True, width="stretch",
            column_config={"Risk": st.column_config.NumberColumn(format="%.2f")})


def _table_or_markdown(text: object, name: str, *, top: bool = False) -> None:
    rows = markdown_table(text)
    if top:
        first = tm_detail.first_mitigation_text(text)
        if first:
            kit.notice(first, tone=Tone.ACCENT, label="Top mitigation")
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        kit.model_markdown(str(text or ""))


def _compliance(record: Record) -> None:
    payload = record.payload
    report = csf_for(record)
    coverage = report.get("coverage") or {}
    kit.section("NIST CSF 2.0 coverage", "Which CSF functions the threats touch.")
    tiles = [kit.Tile(str(fn.get("name") or fid), int(fn.get("threat_count") or 0),
                      ", ".join(fn.get("categories") or []) or "No category",
                      Tone.ACCENT if fn.get("threat_count") else Tone.NEUTRAL)
             for fid, fn in coverage.items() if isinstance(fn, dict)]
    if tiles:
        kit.stat_row(tiles)
    mappings = [m for m in report.get("mappings") or [] if isinstance(m, dict)]
    if mappings:
        kit.section("Per threat")
        st.dataframe(
            [{"Threat": str(m.get("threat_id") or ""), "STRIDE": str(m.get("threat_type") or ""),
              "Technique": str(m.get("technique_id") or ""),
              "CSF categories": ", ".join(f"{c.get('id')} ({c.get('function_name')})"
                                          for c in m.get("categories") or [] if isinstance(c, dict)),
              "Scenario": str(m.get("scenario") or "")} for m in mappings],
            hide_index=True, width="stretch")
    else:
        kit.notice("No threats mapped to NIST CSF.", tone=Tone.NEUTRAL)
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    chosen = [str(c) for c in profile.get("compliance_requirements") or []]
    if chosen:
        kit.section("Frameworks you selected")
        st.html('<div class="tm-chips">' + "".join(f'<span class="tm-chip">{_esc(c)}</span>'
                                                  for c in chosen) + "</div>")
    if is_ai_system(payload):
        _eu_ai_act(record)


def _eu_ai_act(record: Record) -> None:
    kit.section("EU AI Act", "Obligations whose wording overlaps each threat (keyword match, "
                "for review, not a legal reading).")
    try:
        matches = state.session_memo("euai", record.id, lambda: regulation_service.match_threats_to_framework(
            _threats(record.payload), "eu-ai-act"))
    except (ValueError, OSError):
        logger.warning("EU AI Act data could not be read")
        kit.notice("The EU AI Act data could not be read.", tone=Tone.WARN)
        return
    rows = [{"Threat": threat_id, "Article": m.article, "Obligation": m.name,
             "Match": round(m.score, 2)}
            for threat_id, found in matches.items() for m in found]
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        kit.notice("No EU AI Act obligation matched these threats.", tone=Tone.NEUTRAL)


def _lookups(payload: Mapping[str, Any]) -> None:
    kit.section("NVD", "What the National Vulnerability Database returned for the technologies "
                "you listed.")
    kit.model_markdown(str(payload.get("nvd_vulnerabilities_markdown") or "").strip()
                       or "No NVD lookup was made for this run.")
    kit.section("AlienVault OTX", "Recent threat reports for the industry sector.")
    kit.model_markdown(str(payload.get("otx_data_markdown") or "").strip()
                       or "No OTX lookup was made for this run.")


def _suggestions(payload: Mapping[str, Any]) -> None:
    items = [str(s) for s in payload.get("improvement_suggestions") or [] if str(s).strip()]
    if not items:
        return
    with kit.card("suggestions"):
        kit.section("Improvement suggestions", "Add these to the description for a sharper model.")
        kit.model_markdown("\n".join(f"- {item}" for item in items))


# ---------------------------------------------------------------- exports


@dataclass(frozen=True)
class Export:
    """One download: its label, file name, type, icon, and the function that
    builds its bytes (called only when the visitor clicks)."""

    label: str
    file_name: str
    mime: str
    icon: str
    build: Callable[[], bytes | str]
    report: bool = True


def exports(record: Record) -> list[Export]:
    """Every download for a record: five reports, then two plain files."""
    payload = dict(record.payload)
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    description = str(payload.get("description") or "")
    csf = csf_for(record)
    code = str(payload.get("attack_tree_code") or "").strip()
    feature = gherkin_text(payload.get("test_cases_markdown"))

    def pdf() -> bytes:
        return report_service.generate_pdf_bytes(payload, profile, description, nist_csf=csf)

    def html_report() -> str:
        return export_service.to_html_report(payload, profile, description, nist_csf=csf)

    def json_report() -> bytes:
        return export_service.to_json_bytes(
            export_service.to_json_report(payload, profile, description, nist_csf=csf))

    def sarif() -> bytes:
        report = export_service.to_sarif(payload, profile, description, nist_csf=csf)
        return json.dumps(report, indent=2).encode("utf-8")

    return [
        Export("PDF", "aegisshield-report.pdf", "application/pdf", ":material/picture_as_pdf:", pdf),
        Export("HTML", "aegisshield-report.html", "text/html", ":material/code:", html_report),
        Export("JSON", "aegisshield-report.json", "application/json", ":material/data_object:",
               json_report),
        Export("SARIF", "aegisshield.sarif", "application/sarif+json", ":material/bug_report:", sarif),
        Export("Markdown", "aegisshield-threat-model.md", "text/markdown", ":material/description:",
               lambda: bundle_markdown(record)),
        Export("Attack tree (.mmd)", "attack-tree.mmd", "text/plain", ":material/account_tree:",
               lambda: code + "\n" if code else "", report=False),
        Export("Test cases (.feature)", "test-cases.feature", "text/plain", ":material/checklist:",
               lambda: feature, report=False),
    ]


def render_exports(record: Record, *, key_prefix: str = "tm") -> None:
    """Downloads: PDF, HTML, JSON, SARIF, Markdown, the Mermaid tree, and the
    Gherkin test cases. Each file is built only when it is clicked."""
    payload = record.payload
    has = {"Attack tree (.mmd)": bool(str(payload.get("attack_tree_code") or "").strip()),
           "Test cases (.feature)": bool(gherkin_text(payload.get("test_cases_markdown")))}
    items = exports(record)
    for report, title, hint in ((True, "Reports", "PDF to share, HTML to review, JSON for "
                                 "automation, SARIF for code scanning tools. " + PDF_FAILED_HINT),
                                (False, "Files", "The attack tree and the test cases on their own.")):
        kit.section(title, hint)
        with st.container(horizontal=True, key=f"{key_prefix}_exports_{title.lower()}"):
            for item in (i for i in items if i.report is report):
                st.download_button(item.label, data=item.build, file_name=item.file_name,
                                   mime=item.mime, icon=item.icon, on_click="ignore",
                                   type="primary" if item.label == "PDF" else "secondary",
                                   key=f"{key_prefix}_dl_{item.file_name.replace('.', '_')}",
                                   disabled=not has.get(item.label, True))
