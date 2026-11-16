"""Markdown rendering and threat ids shared by both pipeline paths.

Pure functions over the parsed model output. Threat ids look like ``TC-S01``:
the STRIDE letter of the threat type, then a sequence number per letter.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from aegisshield.pipeline import catalog_service
from aegisshield.pipeline.atlas_service import STATUS_TEXT, mapping_rows
from aegisshield.pipeline.mitre_links import (
    atlas_case_study_url,
    atlas_mitigation_url,
    atlas_technique_url,
    is_atlas_technique_id,
)

_STRIDE_LETTER_MAP = [
    ("spoofing", "S"),
    ("tampering", "T"),
    ("repudiation", "R"),
    ("information disclosure", "I"),
    ("info disclosure", "I"),
    ("disclosure", "I"),
    ("denial of service", "D"),
    ("dos", "D"),
    ("elevation of privilege", "E"),
    ("privilege escalation", "E"),
    ("eop", "E"),
]


def _stride_letter(threat_type: str) -> str:
    """The STRIDE letter for a threat type, or ``X`` when none fits."""
    key = (threat_type or "").strip().lower()
    if not key:
        return "X"
    for prefix, letter in _STRIDE_LETTER_MAP:
        if prefix in key:
            return letter
    return "X"


def assign_threat_ids(threat_model: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stamp each threat with an ID like TC-S01, TC-T01 (STRIDE letter + seq)."""
    counters: dict[str, int] = {}
    for threat in threat_model:
        if not isinstance(threat, dict):
            continue
        letter = _stride_letter(str(threat.get("Threat Type", "")))
        counters[letter] = counters.get(letter, 0) + 1
        threat["ID"] = f"TC-{letter}{counters[letter]:02d}"
    return threat_model


def threat_model_to_markdown(threat_model: list[dict[str, Any]], improvement_suggestions: list[str]) -> str:
    """The threats table (with any suggestions) the add-on prompts read."""
    lines: list[str] = []
    lines.append("| ID | Threat Type | Scenario | Potential Impact | Assumptions |")
    lines.append("|----|-------------|----------|------------------|-------------|")

    for threat in threat_model:
        assumptions = threat.get("Assumptions", [])
        if assumptions and isinstance(assumptions, list):
            assumption_text = "<br>".join(
                f"- **{a.get('Assumption', 'N/A')}** (Role: {a.get('Role', 'N/A')}, Condition: {a.get('Condition', 'N/A')})"
                for a in assumptions
                if isinstance(a, dict)
            )
        else:
            assumption_text = "No assumptions provided"

        lines.append(
            "| {id} | {t} | {s} | {p} | {a} |".format(
                id=str(threat.get("ID", "-")).replace("|", "/"),
                t=str(threat.get("Threat Type", "N/A")).replace("|", "/"),
                s=str(threat.get("Scenario", "N/A")).replace("|", "/"),
                p=str(threat.get("Potential Impact", "N/A")).replace("|", "/"),
                a=assumption_text.replace("|", "/"),
            )
        )

    lines.append("\n# Improvement Suggestions\n")
    for suggestion in improvement_suggestions:
        lines.append(f"- {suggestion}")

    return "\n".join(lines).strip() + "\n"


def mitre_data_to_markdown(mitre_data: list[dict[str, Any]]) -> str:
    """One section per threat with its mapped technique and its MITRE link
    (an ATLAS id, which older AI-system records can hold, links to ATLAS)."""
    if not mitre_data:
        return "No MITRE ATT&CK data found.\n"

    chunks: list[str] = []
    for entry in mitre_data:
        threat = entry.get("threat", {})
        threat_id = threat.get("ID", "-")
        threat_type = threat.get("Threat Type", "N/A")
        chunks.append(f"### {threat_id} - {threat_type}")

        techniques = entry.get("mitre_techniques", [])
        if not techniques:
            chunks.append("*No relevant MITRE ATT&CK techniques found.*")
            chunks.append("")
            continue

        for item in techniques:
            name = item.get("name", "N/A")
            description = (item.get("description") or "").strip()
            technique_id = item.get("technique_id", "N/A")
            attack_pattern_id = item.get("id", "N/A")
            if is_atlas_technique_id(technique_id):
                url, site = atlas_technique_url(technique_id) or "", "ATLAS"
            else:
                technique_path = technique_id.replace(".", "/") if technique_id != "N/A" else ""
                url = f"https://attack.mitre.org/techniques/{technique_path}/" if technique_path else ""
                site = "ATT&CK"

            chunks.append(f"#### {technique_id} - {name}")
            if description:
                chunks.append(description)
            meta_parts: list[str] = []
            if url:
                meta_parts.append(f"[View on {site}]({url})")
            meta_parts.append(f"Attack Pattern ID: `{attack_pattern_id}`")
            chunks.append("  \n".join(meta_parts))
            chunks.append("")

    return "\n".join(chunks).strip() + "\n"


_MD_SPECIAL = frozenset("\\`*_{}[]()<>#+-.!|~")
_THREAT_ID = re.compile(r"TC-[A-Z]\d{2,4}")
_VERSION = re.compile(r"\d{1,4}(?:\.\d{1,4}){0,2}")


def _md_text(value: object, limit: int = 200) -> str:
    """Stored text on one line with every markdown sign escaped, so a value
    from an imported record shows as written and cannot add a link."""
    flat = " ".join(str(value or "").split())[:limit]
    return "".join(f"\\{ch}" if ch in _MD_SPECIAL else ch for ch in flat)


def _version(value: object) -> str:
    text = str(value or "")
    return text if _VERSION.fullmatch(text) else "unknown"


def _linked_list(items: object, url_for: Any, names: Mapping[str, str]) -> list[str]:
    out = []
    for item in items if isinstance(items, list) else []:
        item_id = str(item.get("id") or "") if isinstance(item, Mapping) else ""
        url = url_for(item_id)
        if url and item_id in names:
            out.append(f"[{item_id} {_md_text(names[item_id])}]({url})")
    return out


def atlas_mapping_export(mapping: object) -> dict[str, Any] | None:
    """The ATLAS block as data for the JSON and SARIF exports, with links.

    Like the Markdown block, every name, tactic, and link is read from the
    bundled catalog by id; an id that is not in the catalog is left out.
    None for a result without a mapping.
    """
    rows = mapping_rows(mapping)
    if not rows:
        return None
    meta = mapping if isinstance(mapping, Mapping) else {}
    index = catalog_service.atlas_index()
    names = {"mitigations": {m.id: m.name for m in catalog_service.atlas_mitigations()},
             "case_studies": {c.id: c.name for c in catalog_service.atlas_case_studies()}}
    urls = {"mitigations": atlas_mitigation_url, "case_studies": atlas_case_study_url}
    threats = []
    for row in rows:
        technique = row.get("technique") if isinstance(row.get("technique"), Mapping) else {}
        entry = index.get(str(technique.get("technique_id") or ""))
        status = str(row.get("status") or "")
        out: dict[str, Any] = {
            "threat_id": str(row.get("threat_id") or ""),
            "threat_type": str(row.get("threat_type") or ""),
            "status": status if status in STATUS_TEXT else "unknown",
            "technique": None,
        }
        if entry is not None:
            out["technique"] = {"id": entry.technique_id, "name": catalog_service.atlas_display_name(entry),
                                "tactic": entry.tactic, "url": atlas_technique_url(entry.technique_id)}
            for key in ("mitigations", "case_studies"):
                items = row.get(key) if isinstance(row.get(key), list) else []
                ids = [str(i.get("id") or "") for i in items if isinstance(i, Mapping)]
                out[key] = [{"id": i, "name": names[key][i], "url": urls[key](i)} for i in ids if i in names[key]]
                total = row.get(f"{key}_total")
                out[f"{key}_total"] = total if isinstance(total, int) and total >= len(out[key]) else len(out[key])
                source = str(row.get(f"{key}_from") or "")
                out[f"{key}_from"] = source if is_atlas_technique_id(source) else entry.technique_id
        threats.append(out)
    return {"atlas_version": _version(meta.get("atlas_version")),
            "attack_version": _version(meta.get("attack_version")),
            "call": meta.get("call") if meta.get("call") in ("answered", "failed", "none") else "unknown",
            "threats": threats}


def atlas_mapping_to_markdown(mapping: object) -> str:
    """The MITRE ATLAS block of an AI system's threat model, for the exports.

    Ids, names, tactics, mitigations, and case studies are read from the
    bundled catalog by id, never from stored text, and only ids of a known
    shape and in the catalog are linked. Empty for a result without a mapping
    (any other system, or a record saved before ATLAS mapping existed).
    """
    rows = mapping_rows(mapping)
    if not rows:
        return ""
    meta = mapping if isinstance(mapping, Mapping) else {}
    index = catalog_service.atlas_index()
    mitigations = {m.id: m.name for m in catalog_service.atlas_mitigations()}
    studies = {c.id: c.name for c in catalog_service.atlas_case_studies()}
    chunks = [
        f"MITRE ATLAS {_version(meta.get('atlas_version'))} technique for each threat, alongside its "
        f"MITRE ATT&CK {_version(meta.get('attack_version'))} technique. Mitigations and case studies "
        "are the ones the ATLAS catalog links to the technique; the model did not write them.",
        "",
    ]
    if meta.get("call") == "failed":
        chunks += ["*The ATLAS step did not finish, so no ATLAS technique was mapped.*", ""]
    for row in rows:
        threat_id = str(row.get("threat_id") or "")
        threat_id = threat_id if _THREAT_ID.fullmatch(threat_id) else "-"
        chunks.append(f"### {threat_id} - {_md_text(row.get('threat_type') or 'N/A')}")
        technique = row.get("technique") if isinstance(row.get("technique"), Mapping) else {}
        entry = index.get(str(technique.get("technique_id") or ""))
        if entry is None:
            status = str(row.get("status") or "")
            chunks += [f"*{STATUS_TEXT.get(status, 'No ATLAS technique.')}*", ""]
            continue
        name = _md_text(catalog_service.atlas_display_name(entry))
        chunks.append(f"**Technique:** [{entry.technique_id} {name}]({atlas_technique_url(entry.technique_id)}) "
                      f"({_md_text(entry.tactic)})")
        for label, key, url_for, names in (("Mitigations", "mitigations", atlas_mitigation_url, mitigations),
                                           ("Case studies", "case_studies", atlas_case_study_url, studies)):
            links = _linked_list(row.get(key), url_for, names)
            total = row.get(f"{key}_total")
            total = total if isinstance(total, int) and total >= len(links) else len(links)
            source = str(row.get(f"{key}_from") or "")
            note = (f", listed for the parent technique {source}"
                    if source != entry.technique_id and is_atlas_technique_id(source) else "")
            if links:
                chunks.append(f"**{label}** ({len(links)} of {total}{note}): " + "; ".join(links))
            else:
                chunks.append(f"**{label}:** none in the ATLAS catalog for this technique.")
        chunks.append("")
    return "\n".join(chunks).strip() + "\n"


def nvd_to_markdown(nvd_vulnerabilities: dict[str, str]) -> str:
    """The NVD prompt text per technology, one entry per block."""
    if not nvd_vulnerabilities:
        return "No NVD vulnerabilities found.\n"

    chunks: list[str] = []
    for tech_version, vulnerabilities in nvd_vulnerabilities.items():
        chunks.append(f"#### {tech_version}")
        if isinstance(vulnerabilities, str):
            for vuln in vulnerabilities.split("|"):
                text = vuln.strip()
                if text:
                    chunks.append(text)
                    chunks.append("---")
        else:
            chunks.append(f"Unexpected data type for {tech_version}: {type(vulnerabilities)}")

    return "\n".join(chunks).strip() + "\n"
