"""Map threat-model output onto NIST CSF 2.0 functions and categories.

A pure data transform with no model calls: each threat (the shape the
threat-model job returns) is tagged with the CSF categories most likely to
apply.

Two signals drive the mapping, and their categories are unioned in order:

1. The threat's STRIDE category (``Threat Type``) gives a baseline from
   ``stride_to_csf`` in the packaged ``nist/csf-2.0.json``.
2. The tactic of the threat's top mapped MITRE technique (from
   ``mitre_data``) adds categories from ``tactic_to_csf``.

So an "Information Disclosure" threat mapped to the "Exfiltration" tactic
gets PR.DS, PR.AA, DE.CM, and RS.MI. The JSON file is the source of truth;
changing the mapping is a data edit, not code.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any

from aegisshield.data import data_path

NIST_CSF_FILE = ("nist", "csf-2.0.json")

# Shown in a markdown cell that has no value.
EMPTY_CELL = "-"

_SPACE_RE = re.compile(r"[\s_-]+")
_LINE_RE = re.compile(r"[\r\n\t]+")


@dataclass(frozen=True)
class CsfCategory:
    """One CSF 2.0 category and the function it belongs to."""

    id: str
    name: str
    function_id: str
    function_name: str


@dataclass(frozen=True)
class ThreatCsfMapping:
    """One threat and the CSF categories mapped to it, in signal order."""

    threat_id: str | None
    threat_type: str
    scenario: str
    technique_id: str | None
    categories: list[CsfCategory]


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    """The packaged CSF mapping. Public reference data, so a process cache is fine."""
    with data_path(*NIST_CSF_FILE).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _category_index() -> tuple[dict[str, CsfCategory], dict[str, dict[str, Any]]]:
    """Categories by id and raw functions by id (the policy service unpacks
    both)."""
    by_id: dict[str, CsfCategory] = {}
    functions_by_id: dict[str, dict[str, Any]] = {}
    for fn in _load().get("functions", []):
        functions_by_id[fn["id"]] = copy.deepcopy(fn)
        for cat in fn.get("categories", []):
            by_id[cat["id"]] = CsfCategory(
                id=cat["id"],
                name=cat["name"],
                function_id=fn["id"],
                function_name=fn["name"],
            )
    return by_id, functions_by_id


def category_index() -> dict[str, CsfCategory]:
    """Every CSF 2.0 category by id (for example ``"PR.AA"``)."""
    return _category_index()[0]


def _tactic_key(tactic: object) -> str:
    """Normalize a tactic name so "command-and-control" matches "Command and Control".

    The ATT&CK catalog builds tactic names with ``str.title()`` ("Command And
    Control", "Ml Attack Staging"), which never matched the mapping's keys
    when compared exactly.
    """
    if not isinstance(tactic, str):
        return ""
    return _SPACE_RE.sub(" ", tactic).strip().lower()


def map_threats(
    threat_model: list[dict[str, Any]], mitre_data: list[dict[str, Any]] | None = None
) -> list[ThreatCsfMapping]:
    """Map each threat to the NIST CSF categories that most apply.

    ``mitre_data`` is the list the MITRE step returns (``{"threat": {...},
    "mitre_techniques": [...]}`` per threat). When given, the tactic of each
    threat's first technique adds categories beyond the STRIDE baseline.
    Threats are matched to MITRE entries by ``ID``, or by ``Scenario`` when
    there is no ID.
    """
    data = _load()
    categories = category_index()
    stride_map: dict[str, list[str]] = data.get("stride_to_csf", {}) or {}
    tactic_map = {
        _tactic_key(name): ids for name, ids in (data.get("tactic_to_csf", {}) or {}).items()
    }

    tactic_for_threat: dict[str, str | None] = {}
    technique_for_threat: dict[str, str | None] = {}
    for entry in mitre_data or []:
        if not isinstance(entry, dict):
            continue
        threat = entry.get("threat") or {}
        if not isinstance(threat, dict):
            continue
        key = str(threat.get("ID") or threat.get("Scenario") or "")
        techs = entry.get("mitre_techniques") or []
        if not isinstance(techs, list) or not techs or not isinstance(techs[0], dict):
            continue
        top = techs[0]
        tactic_for_threat[key] = top.get("tactic")
        technique_for_threat[key] = top.get("technique_id")

    out: list[ThreatCsfMapping] = []
    for threat in threat_model:
        threat_type = str(threat.get("Threat Type", "")).strip()
        scenario = str(threat.get("Scenario", "")).strip()
        threat_id = threat.get("ID")
        key = str(threat_id or scenario)

        cat_ids: list[str] = []
        for cid in stride_map.get(threat_type, []):
            if cid not in cat_ids:
                cat_ids.append(cid)
        tactic = _tactic_key(tactic_for_threat.get(key))
        if tactic:
            for cid in tactic_map.get(tactic, []):
                if cid not in cat_ids:
                    cat_ids.append(cid)

        out.append(
            ThreatCsfMapping(
                threat_id=str(threat_id) if threat_id else None,
                threat_type=threat_type,
                scenario=scenario,
                technique_id=technique_for_threat.get(key),
                categories=[categories[cid] for cid in cat_ids if cid in categories],
            )
        )
    return out


def coverage_summary(mappings: list[ThreatCsfMapping]) -> dict[str, dict[str, Any]]:
    """Per CSF function: name, summary, how many threats touched it, and which categories.

    Keys are the function ids (GV, ID, PR, DE, RS, RC) in file order;
    ``categories`` is a sorted list of the category ids seen.
    """
    out: dict[str, dict[str, Any]] = {
        fn["id"]: {
            "name": fn["name"],
            "summary": fn["summary"],
            "threat_count": 0,
            "categories": [],
        }
        for fn in _load().get("functions", [])
    }
    seen: dict[str, set[str]] = {fn_id: set() for fn_id in out}
    for mapping in mappings:
        functions_hit: set[str] = set()
        for cat in mapping.categories:
            if cat.function_id not in seen:
                continue
            seen[cat.function_id].add(cat.id)
            functions_hit.add(cat.function_id)
        for fid in functions_hit:
            out[fid]["threat_count"] += 1
    for fid in out:
        out[fid]["categories"] = sorted(seen[fid])
    return out


def to_markdown(mappings: list[ThreatCsfMapping]) -> str:
    """Render the mapping as a markdown table for the PDF and HTML reports.

    Every cell is escaped, since the scenario, threat type, and technique id
    all come from model output.
    """
    if not mappings:
        return "_No threats mapped to NIST CSF._"
    lines = [
        "| Threat | STRIDE | Technique | NIST CSF |",
        "|---|---|---|---|",
    ]
    for m in mappings:
        cats = ", ".join(f"{c.id} ({c.function_name})" for c in m.categories)
        lines.append(
            f"| {_cell(m.scenario)} | {_cell(m.threat_type)} | "
            f"{_cell(m.technique_id)} | {_cell(cats)} |"
        )
    return "\n".join(lines)


def csf_report(
    threat_model: list[dict[str, Any]], mitre_data: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """The mapping as plain JSON values: ``mappings``, ``coverage``, and ``markdown``.

    This is what the exporters accept as their NIST CSF section.
    """
    mappings = map_threats(threat_model, mitre_data)
    return {
        "mappings": [asdict(m) for m in mappings],
        "coverage": coverage_summary(mappings),
        "markdown": to_markdown(mappings),
    }


def _cell(text: str | None) -> str:
    """One markdown table cell: line breaks become spaces and pipes are escaped."""
    value = _LINE_RE.sub(" ", text or "").strip()
    if not value:
        return EMPTY_CELL
    return value.replace("|", "\\|")
