"""Application checks on a finished threat model: form and references.

These are plain code, not rails, and they check two things only:

- Form: every threat and every section the run was asked for is there and
  has the shape the pipeline produces; each STRIDE category is one of the
  six; each DREAD score is a number in range and the risk matches the app's
  own formula.
- References: each CVE id, technique id, threat id, and named technology
  version in the output points at something the run was given (the NVD
  results, the technique catalog, the threat list, the request).

They do not judge whether a finding is right. An unresolved reference is
flagged "unsupported reference, review", never removed and never called
false. Each flag has a stable code, the place it applies to (threat id and
field), and a plain sentence; ``review_flags`` returns them as JSON-safe
dicts for the result's ``REVIEW_FLAGS_KEY``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from aegisshield.core.errors import LLMResponseError
from aegisshield.services import tech_products

REVIEW_FLAGS_KEY = "review_flags"

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
# What the STRIDE prompt asks for per threat (threat_model_service), plus the
# id the pipeline stamps (formatting_service.assign_threat_ids). Assumptions
# must be a list; an empty one is valid (the table shows "No assumptions
# provided").
REQUIRED_TEXT_FIELDS = ("ID", "Threat Type", "Scenario", "Potential Impact")
DREAD_AXES = ("Damage Potential", "Reproducibility", "Exploitability", "Affected Users",
              "Discoverability")
# The DREAD prompt asks for integers from 1 to 10.
DREAD_MIN, DREAD_MAX = 1, 10
_SCORE_TOLERANCE = 0.01

# The sections a run may be asked for, and the result key each one fills.
_ADDON_KEYS = {"mitigations": "mitigations_markdown", "dread": "dread_assessment",
               "test_cases": "test_cases_markdown"}
_SECTION_KEYS = {"STRIDE": "threat_model", "MITRE": "mitre_data", "DREAD": "dread_assessment",
                 "MITIGATIONS": "mitigations_markdown", "TEST_CASES": "test_cases_markdown",
                 "TEAMMATE": "teammate_review", "REBUTTAL": "rebuttal_review"}
# Model-written parts of a result, where references are looked for.
_MODEL_TEXT_KEYS = ("threat_model", "improvement_suggestions", "attack_tree_code",
                    "mitigations_markdown", "dread_assessment", "test_cases_markdown",
                    "teammate_review", "rebuttal_review")

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"(?<![\w.])(?:AML\.)?T\d{4}(?:\.\d{3})?\b")
_THREAT_ID_RE = re.compile(r"\bTC-[A-Z]\d{2,4}\b")
_TABLE_ID_RE = re.compile(r"^\|\s*(TC-[A-Z]\d{2,4})\s*\|", re.MULTILINE)
_DREAD_ROW_RE = re.compile(
    r"^\|\s*(?P<id>[^|\n]{1,40}?)\s*\|\s*(?P<d>[\d.]{1,6})\s*\|\s*(?P<r>[\d.]{1,6})\s*\|"
    r"\s*(?P<e>[\d.]{1,6})\s*\|\s*(?P<a>[\d.]{1,6})\s*\|\s*(?P<di>[\d.]{1,6})\s*\|"
    r"\s*(?P<risk>[\d.]{1,6})\s*\|",
    re.MULTILINE,
)
_VERSION_RE = re.compile(r"(?<![\w.])v?(\d{1,6}(?:\.\d{1,6}){1,3})\b")
_NAME_WORD_RE = re.compile(r"[A-Za-z0-9+#.\-]{1,40}")
_NAME_WINDOW = 60

CHECKS_NOTE = (
    "These are checks of form and of references: they look at the shape of the result and "
    "whether what it cites was supplied to the run. They do not judge whether a finding is right."
)


@dataclass(frozen=True)
class ReviewFlag:
    """One review flag: a stable code, where it applies, and a plain sentence."""

    code: str
    sentence: str
    threat_id: str | None = None
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "threat_id": self.threat_id, "field": self.field,
                "sentence": self.sentence}


def _texts(value: Any) -> Iterable[str]:
    """Every string inside ``value``."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, str):
                yield k
            yield from _texts(v)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _texts(item)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _threat_ids(result: Mapping[str, Any]) -> set[str]:
    threats = result.get("threat_model")
    if not isinstance(threats, list):
        return set()
    return {str(t.get("ID")) for t in threats if isinstance(t, dict) and t.get("ID")}


# ----------------------------------------------------------------- form


def _check_threats(result: Mapping[str, Any], flags: list[ReviewFlag]) -> None:
    threats = result.get("threat_model")
    if not isinstance(threats, list):
        flags.append(ReviewFlag("structure", "The threat list is not a list.", field="threat_model"))
        return
    if not threats:
        flags.append(ReviewFlag("missing_section", "The run returned no threats.", field="threat_model"))
    allowed = {c.lower() for c in STRIDE_CATEGORIES}
    for index, threat in enumerate(threats, start=1):
        if not isinstance(threat, dict):
            flags.append(ReviewFlag("structure", f"Threat {index} is not an object.",
                                    field="threat_model"))
            continue
        tid = str(threat.get("ID") or "") or None
        where = tid or f"threat {index}"
        for name in REQUIRED_TEXT_FIELDS:
            value = threat.get(name)
            if not isinstance(value, str) or not value.strip():
                flags.append(ReviewFlag("missing_field", f"{where} has no {name}.", tid, name))
        keywords = threat.get("MITRE ATT&CK Keywords")
        if not isinstance(keywords, list) or not any(isinstance(k, str) and k.strip() for k in keywords):
            flags.append(ReviewFlag("missing_field", f"{where} has no MITRE ATT&CK keywords.", tid,
                                    "MITRE ATT&CK Keywords"))
        if not isinstance(threat.get("Assumptions"), list):
            flags.append(ReviewFlag("structure", f"{where} has assumptions that are not a list.", tid,
                                    "Assumptions"))
        category = threat.get("Threat Type")
        if isinstance(category, str) and category.strip() and category.strip().lower() not in allowed:
            flags.append(ReviewFlag("stride_category",
                                    f"{where} has a threat type that is not one of the six STRIDE "
                                    "categories.", tid, "Threat Type"))


def _check_sections(result: Mapping[str, Any], addons: Iterable[str] | None,
                    flags: list[ReviewFlag]) -> None:
    if result.get("agentic"):
        plan = result.get("lead_plan") if isinstance(result.get("lead_plan"), Mapping) else {}
        asked = [str(p.get("section")) for p in plan.get("sections", [])
                 if isinstance(p, Mapping) and not p.get("skip")]
        wanted = [_SECTION_KEYS[s] for s in asked if s in _SECTION_KEYS]
    else:
        wanted = [_ADDON_KEYS[a] for a in addons or () if a in _ADDON_KEYS]
    for key in ("attack_tree_code", "mitre_data", *wanted):
        value = result.get(key)
        empty = value is None or (isinstance(value, str | list | dict) and not value)
        if empty:
            flags.append(ReviewFlag("missing_section",
                                    f"The run was asked for {key.replace('_', ' ')} and it is missing.",
                                    field=key))
    if not isinstance(result.get("improvement_suggestions", []), list) or not all(
        isinstance(s, str) for s in result.get("improvement_suggestions", [])
    ):
        flags.append(ReviewFlag("structure", "The improvement suggestions are not a list of text.",
                                field="improvement_suggestions"))
    mitre = result.get("mitre_data")
    if mitre is not None and (not isinstance(mitre, list) or not all(
        isinstance(m, Mapping) and isinstance(m.get("mitre_techniques"), list) for m in mitre
    )):
        flags.append(ReviewFlag("structure", "The technique mapping does not have the expected shape.",
                                field="mitre_data"))


def _check_dread(result: Mapping[str, Any], flags: list[ReviewFlag]) -> None:
    assessment = result.get("dread_assessment")
    if assessment is None:
        return
    if not isinstance(assessment, dict):
        flags.append(ReviewFlag("structure", "The DREAD assessment is not an object.",
                                field="dread_assessment"))
        return
    # Imported here: the pipeline imports this module when it loads.
    from aegisshield.pipeline.dread_service import dread_json_to_markdown

    try:
        # The renderer the pipeline uses; it raises on a shape it cannot read.
        dread_json_to_markdown(assessment)
    except (LLMResponseError, TypeError, ValueError):
        flags.append(ReviewFlag("structure", "The DREAD assessment does not have the expected shape.",
                                field="dread_assessment"))
        return
    for row in assessment.get("Risk Assessment", []):
        tid = str(row.get("ID") or "") or None
        where = tid or "A DREAD row"
        values: list[float] = []
        for axis in DREAD_AXES:
            value = row.get(axis)
            if not _is_number(value) or not DREAD_MIN <= value <= DREAD_MAX:
                flags.append(ReviewFlag("dread_range",
                                        f"{where} has a {axis} score that is not a number from "
                                        f"{DREAD_MIN} to {DREAD_MAX}.", tid, axis))
            else:
                values.append(float(value))
        if "Risk Score" in row and len(values) == len(DREAD_AXES):
            stated = row.get("Risk Score")
            if not _is_number(stated) or abs(float(stated) - sum(values) / len(values)) > _SCORE_TOLERANCE:
                flags.append(ReviewFlag("dread_score",
                                        f"{where} has a risk score that is not the mean of its five "
                                        "scores.", tid, "Risk Score"))
    table = result.get("dread_assessment_markdown")
    if isinstance(table, str):
        for m in _DREAD_ROW_RE.finditer(table):
            try:
                axes = [float(m.group(g)) for g in ("d", "r", "e", "a", "di")]
                risk = float(m.group("risk"))
            except ValueError:
                continue
            if abs(risk - sum(axes) / len(axes)) > _SCORE_TOLERANCE:
                tid = m.group("id").strip()
                flags.append(ReviewFlag("dread_score",
                                        f"{tid} has a risk score in the DREAD table that is not the "
                                        "mean of its five scores.", tid, "Risk Score"))


# ----------------------------------------------------------------- references


def _unsupported(code: str, what: str, where: str, tid: str | None, field: str) -> ReviewFlag:
    return ReviewFlag(code, f"Unsupported reference, review: {what} {where}.", tid, field)


def _model_fields(result: Mapping[str, Any]) -> Iterable[tuple[str | None, str, str]]:
    """``(threat id, field, text)`` for every model-written string in the result."""
    threats = result.get("threat_model")
    if isinstance(threats, list):
        for threat in threats:
            if isinstance(threat, dict):
                tid = str(threat.get("ID") or "") or None
                for name, value in threat.items():
                    if name != "ID":
                        for text in _texts(value):
                            yield tid, name, text
    for key in _MODEL_TEXT_KEYS[1:]:
        for text in _texts(result.get(key)):
            yield None, key, text


def _named_versions(text: str) -> Iterable[tuple[str, str]]:
    """``(product name, version)`` for each version number that follows a
    known product name (up to four words, on the same line)."""
    for m in _VERSION_RE.finditer(text):
        line_start = text.rfind("\n", max(0, m.start() - _NAME_WINDOW), m.start()) + 1
        words = _NAME_WORD_RE.findall(text[max(line_start, m.start() - _NAME_WINDOW):m.start()])
        for size in range(min(4, len(words)), 0, -1):
            name = " ".join(words[-size:])
            if tech_products.product_for(name) is not None:
                yield name, m.group(1)
                break


def _requested_versions(profile: Mapping[str, Any]) -> dict[str, set[str]]:
    """Product key to the versions the request listed ("*" for any)."""
    techs = profile.get("selected_technologies") or {}
    versions = profile.get("selected_versions") or {}
    found: dict[str, set[str]] = {}
    for name in techs:
        ref = tech_products.product_for(str(name))
        key = f"{ref.vendor}:{ref.product}" if ref else str(name).strip().lower()
        found.setdefault(key, set()).add(str(versions.get(name) or "*").strip() or "*")
    return found


def _str_items(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _check_references(result: Mapping[str, Any], profile: Mapping[str, Any],
                      flags: list[ReviewFlag]) -> None:
    from aegisshield.pipeline.catalog_service import atlas_index, catalog_for_app_type, index_by_id

    supplied_cves = {c.upper() for c in _CVE_RE.findall(str(result.get("nvd_vulnerabilities_markdown") or ""))}
    patterns = [*_str_items(profile.get("app_pattern")), *_str_items(result.get("detected_patterns"))]
    catalog = index_by_id(catalog_for_app_type(str(profile.get("app_type") or ""), patterns))
    threat_ids = _threat_ids(result)
    requested = _requested_versions(profile)
    seen: set[tuple[str, str | None, str]] = set()

    def flag_once(code: str, what: str, where: str, tid: str | None, field: str) -> None:
        if (what, tid, field) not in seen:
            seen.add((what, tid, field))
            flags.append(_unsupported(code, what, where, tid, field))

    for tid, field, text in _model_fields(result):
        for cve in _CVE_RE.findall(text):
            if cve.upper() not in supplied_cves:
                flag_once("unsupported_cve", cve.upper(), "is not in the NVD results supplied to this run",
                          tid, field)
        for technique in _TECHNIQUE_RE.findall(text):
            if technique not in catalog:
                flag_once("unsupported_technique", technique,
                          "is not in the technique catalog this run used", tid, field)
        if tid is None:
            for ref_id in _THREAT_ID_RE.findall(text):
                if ref_id not in threat_ids:
                    flag_once("unknown_threat_id", ref_id, "points to a threat that is not in the threat list",
                              None, field)
        for name, version in _named_versions(text):
            ref = tech_products.product_for(name)
            key = f"{ref.vendor}:{ref.product}" if ref else name.lower()
            listed = requested.get(key)
            if listed is None or ("*" not in listed and version not in listed):
                flag_once("unsupported_technology", f"{name} {version}",
                          "is not a technology and version the request listed", tid, field)
    for entry in result.get("mitre_data") or []:
        if not isinstance(entry, Mapping):
            continue
        threat = entry.get("threat") if isinstance(entry.get("threat"), Mapping) else {}
        tid = str(threat.get("ID") or "") or None
        for technique in entry.get("mitre_techniques") or []:
            tech_id = str(technique.get("technique_id") or "") if isinstance(technique, Mapping) else ""
            if tech_id and tech_id not in catalog:
                flag_once("unsupported_technique", tech_id,
                          "is not in the technique catalog this run used", tid, "mitre_data")
        if tid and tid not in threat_ids:
            flag_once("unknown_threat_id", tid, "points to a threat that is not in the threat list",
                      None, "mitre_data")
    atlas = result.get("atlas_mapping")
    rows = atlas.get("threats") if isinstance(atlas, Mapping) else None
    for row in rows if isinstance(rows, list) else []:
        technique = row.get("technique") if isinstance(row, Mapping) else None
        if not isinstance(technique, Mapping):
            continue
        tid = str(row.get("threat_id") or "") or None
        tech_id = str(technique.get("technique_id") or "")
        if tech_id not in atlas_index():
            flag_once("unsupported_technique", tech_id or "(no id)",
                      "is not in the MITRE ATLAS catalog this app ships", tid, "atlas_mapping")
    assessment = result.get("dread_assessment")
    rows = assessment.get("Risk Assessment", []) if isinstance(assessment, dict) else []
    for row in rows if isinstance(rows, list) else []:
        rid = str(row.get("ID") or "") if isinstance(row, dict) else ""
        if rid and rid not in threat_ids:
            flag_once("unknown_threat_id", rid, "points to a threat that is not in the threat list",
                      None, "dread_assessment")
    for key in ("mitigations_markdown", "test_cases_markdown"):
        for rid in _TABLE_ID_RE.findall(str(result.get(key) or "")):
            if rid not in threat_ids:
                flag_once("unknown_threat_id", rid, "points to a threat that is not in the threat list",
                          None, key)


def review_flags(result: Mapping[str, Any], *, profile: Mapping[str, Any],
                 addons: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """The review flags for a finished threat-model result.

    ``profile`` is the request's profile (its app type picks the technique
    catalog; its technologies and versions are what may be named as
    affected). ``addons`` are the linear run's requested add-ons; an agentic
    run's sections are read from its ``lead_plan``.
    """
    flags: list[ReviewFlag] = []
    _check_threats(result, flags)
    _check_sections(result, addons, flags)
    _check_dread(result, flags)
    _check_references(result, profile, flags)
    return [f.to_dict() for f in flags]


__all__ = [
    "CHECKS_NOTE",
    "DREAD_AXES",
    "REVIEW_FLAGS_KEY",
    "STRIDE_CATEGORIES",
    "ReviewFlag",
    "review_flags",
]
