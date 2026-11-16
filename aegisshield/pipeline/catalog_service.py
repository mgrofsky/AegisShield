"""Pinned ATT&CK + ATLAS catalog loader and validator.

A model asked for ATT&CK technique ids can name one that is not in the
dataset. This module loads the pinned bundles into a flat list of
``CatalogEntry`` records and exposes ``validate_id`` so any ID returned by the model can be checked
against the catalog before it leaves the workflow.

The MITRE ATT&CK STIX bundles (release 20.1) come from
``aegisshield.data.mitre_data_dir()``. The MITRE ATLAS catalog (release
2026.10: tactics, techniques and sub-techniques, mitigations, and case
studies) is ``aegisshield/data/atlas/atlas-2026-10.json``, converted from
the official release by ``tools/refresh_mitre.py``. Both SOURCE.md files say
where each file came from. The versions shown to visitors are read from the
data itself.

Parsed catalogs are cached for the life of the process: they are public
reference data, the same for every visitor, and the enterprise bundle is
large.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from aegisshield.data import data_path, mitre_data_dir
from aegisshield.pipeline.ai_system import is_ai_system

ATTACK_DOMAIN_FILES = {
    "enterprise": "enterprise-attack.json",
    "mobile": "mobile-attack.json",
    "ics": "ics-attack.json",
}

ATLAS_FILE = "atlas-2026-10.json"


@dataclass(frozen=True)
class CatalogEntry:
    """A single attack technique, normalised across ATT&CK + ATLAS."""

    framework: str  # "ATT&CK" or "ATLAS"
    domain: str  # "enterprise" / "mobile" / "ics" / "atlas"
    technique_id: str  # e.g. "T1059" or "AML.T0051"
    stix_id: str | None  # e.g. "attack-pattern--..." (None for ATLAS)
    name: str
    tactic: str
    description: str

    def short_description(self, limit: int = 280) -> str:
        """The description on one line, cut to ``limit`` characters."""
        text = self.description.strip().replace("\n", " ")
        return (text[: limit - 3] + "...") if len(text) > limit else text


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _attack_pattern_to_entry(obj: dict[str, Any], domain: str) -> CatalogEntry | None:
    if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    technique_id: str | None = None
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            technique_id = ref["external_id"]
            break
    if not technique_id:
        return None

    tactic = "Unknown"
    phases = obj.get("kill_chain_phases", []) or []
    if phases:
        tactic = phases[0].get("phase_name", "Unknown").replace("-", " ").title()

    return CatalogEntry(
        framework="ATT&CK",
        domain=domain,
        technique_id=technique_id,
        stix_id=obj.get("id"),
        name=obj.get("name", "Unknown"),
        tactic=tactic,
        description=obj.get("description", "") or "",
    )


def _atlas_to_entry(obj: dict[str, Any]) -> CatalogEntry:
    """An ATLAS technique or sub-technique; its tactic is the first one listed, as for ATT&CK."""
    tactics = obj.get("tactics") or []
    return CatalogEntry(
        framework="ATLAS",
        domain="atlas",
        technique_id=obj["id"],
        stix_id=None,
        name=obj.get("name", "Unknown"),
        tactic=tactics[0]["name"] if tactics else "Unknown",
        description=obj.get("description", "") or "",
    )


@lru_cache(maxsize=len(ATTACK_DOMAIN_FILES))
def _domain_data(domain: str) -> tuple[tuple[CatalogEntry, ...], str]:
    """A domain's live techniques and its release version, from one read of the bundle."""
    bundle = _load_json(mitre_data_dir() / ATTACK_DOMAIN_FILES[domain])
    objects = bundle.get("objects", []) or []
    entries = (_attack_pattern_to_entry(obj, domain) for obj in objects)
    version = next((str(obj.get("x_mitre_version", "unknown")) for obj in objects
                    if obj.get("type") == "x-mitre-collection"), "unknown")
    return tuple(entry for entry in entries if entry is not None), version


def _domain_entries(domain: str) -> tuple[CatalogEntry, ...]:
    return _domain_data(domain)[0]


def _domain_version(domain: str) -> str:
    return _domain_data(domain)[1]


def attack_version() -> str:
    """The ATT&CK release the bundles hold (for example ``20.1``), read from the data.

    The three bundles come from one release; if they ever differ, each
    domain's version is named.
    """
    versions = {domain: _domain_version(domain) for domain in ATTACK_DOMAIN_FILES}
    if len(set(versions.values())) == 1:
        return next(iter(versions.values()))
    return ", ".join(f"{domain} {version}" for domain, version in versions.items())


def load_attack_entries(domains: Iterable[str]) -> list[CatalogEntry]:
    """The live ATT&CK techniques of each known domain, in bundle order."""
    entries: list[CatalogEntry] = []
    for domain in domains:
        if domain in ATTACK_DOMAIN_FILES:
            entries.extend(_domain_entries(domain))
    return entries


@dataclass(frozen=True)
class AtlasTactic:
    """An ATLAS tactic, as published."""

    id: str
    name: str
    description: str


@dataclass(frozen=True)
class AtlasMitigation:
    """An ATLAS mitigation and the technique ids it addresses."""

    id: str
    name: str
    description: str
    technique_ids: tuple[str, ...]


@dataclass(frozen=True)
class AtlasCaseStudy:
    """An ATLAS case study: its summary and the technique ids it used."""

    id: str
    name: str
    summary: str
    technique_ids: tuple[str, ...]


@lru_cache(maxsize=1)
def _atlas_data() -> dict[str, Any]:
    return _load_json(data_path("atlas", ATLAS_FILE))


@lru_cache(maxsize=1)
def _atlas_entries() -> tuple[CatalogEntry, ...]:
    return tuple(_atlas_to_entry(obj) for obj in _atlas_data().get("techniques", []))


def load_atlas_entries() -> list[CatalogEntry]:
    """Every packaged ATLAS technique and sub-technique, in release order."""
    return list(_atlas_entries())


@lru_cache(maxsize=1)
def atlas_index() -> dict[str, CatalogEntry]:
    """Every ATLAS technique and sub-technique by id."""
    return {entry.technique_id: entry for entry in _atlas_entries()}


def atlas_display_name(entry: CatalogEntry) -> str:
    """An ATLAS entry's name as ATLAS shows it: a sub-technique is named after
    its parent ("LLM Prompt Injection: Direct"), since "Direct" alone says little."""
    parent_id, dot, suffix = entry.technique_id.rpartition(".")
    if dot and suffix.isdigit() and parent_id.startswith("AML.T"):
        parent = atlas_index().get(parent_id)
        if parent is not None:
            return f"{parent.name}: {entry.name}"
    return entry.name


def atlas_version() -> str:
    """The ATLAS release the packaged file holds (for example ``2026.10``), read from the data."""
    return str(_atlas_data().get("version", "unknown"))


@lru_cache(maxsize=1)
def atlas_tactics() -> tuple[AtlasTactic, ...]:
    """The ATLAS tactics, in matrix order."""
    return tuple(AtlasTactic(t["id"], t["name"], t.get("description", "") or "")
                 for t in _atlas_data().get("tactics", []))


@lru_cache(maxsize=1)
def atlas_mitigations() -> tuple[AtlasMitigation, ...]:
    """Every ATLAS mitigation, in release order."""
    return tuple(AtlasMitigation(m["id"], m["name"], m.get("description", "") or "",
                                 tuple(m.get("techniques", [])))
                 for m in _atlas_data().get("mitigations", []))


@lru_cache(maxsize=1)
def atlas_case_studies() -> tuple[AtlasCaseStudy, ...]:
    """Every ATLAS case study, in release order."""
    return tuple(AtlasCaseStudy(c["id"], c["name"], c.get("summary", "") or "",
                                tuple(c.get("techniques", [])))
                 for c in _atlas_data().get("case_studies", []))


def _group_by_technique(items: Iterable[Any]) -> dict[str, tuple[Any, ...]]:
    grouped: dict[str, list[Any]] = {}
    for item in items:
        for technique_id in item.technique_ids:
            grouped.setdefault(technique_id, []).append(item)
    return {key: tuple(value) for key, value in grouped.items()}


@lru_cache(maxsize=1)
def _mitigations_by_technique() -> dict[str, tuple[AtlasMitigation, ...]]:
    return _group_by_technique(atlas_mitigations())


@lru_cache(maxsize=1)
def _case_studies_by_technique() -> dict[str, tuple[AtlasCaseStudy, ...]]:
    return _group_by_technique(atlas_case_studies())


def atlas_mitigations_for(technique_id: str) -> tuple[AtlasMitigation, ...]:
    """The ATLAS mitigations that list exactly this technique id (a sub-technique
    does not inherit its parent's); empty for an unknown id."""
    return _mitigations_by_technique().get(technique_id, ())


def atlas_case_studies_for(technique_id: str) -> tuple[AtlasCaseStudy, ...]:
    """The ATLAS case studies that used exactly this technique id; empty for an unknown id."""
    return _case_studies_by_technique().get(technique_id, ())


def build_catalog(domains: Iterable[str], include_atlas: bool) -> list[CatalogEntry]:
    """ATT&CK entries for ``domains``, plus ATLAS when ``include_atlas``."""
    entries = load_attack_entries(domains)
    if include_atlas:
        entries.extend(load_atlas_entries())
    return entries


def index_by_id(entries: Iterable[CatalogEntry]) -> dict[str, CatalogEntry]:
    """Index by both technique_id and stix_id, for fast validation."""

    index: dict[str, CatalogEntry] = {}
    for entry in entries:
        index[entry.technique_id] = entry
        if entry.stix_id:
            index[entry.stix_id] = entry
    return index


def validate_id(catalog_index: dict[str, CatalogEntry], candidate: str) -> CatalogEntry | None:
    """Return the matching entry, or None when the candidate is not in the catalog."""

    if not isinstance(candidate, str) or not candidate.strip():
        return None
    return catalog_index.get(candidate.strip())


# App-type to catalog selection. This replaces the older MOBILE/ICS/ENTERPRISE
# routing in ``mitre_service.py`` while keeping its existing behaviour.

_MOBILE_APP_TYPES = {
    "Mobile application",
    "5G/Wireless System",
}

_ICS_APP_TYPES = {
    "ICS or SCADA System",
    "Smart Grid Systems",
    "Industrial Internet of Things (IIoT)",
    "Cyber-Physical System (CPS)",
    "Vehicular Fog Computing (VFC)",
    "Embedded systems",
    "IoT application",
    "Fog Computing",
    "Wearable Devices",
}

def domains_for_app_type(app_type: str, patterns: Iterable[str] = ()) -> tuple[list[str], bool]:
    """Pick which ATT&CK domains and whether to include ATLAS.

    Returns ``(domains, include_atlas)``. Enterprise is always included so we
    always have a baseline catalog even when the app type is unrecognised.
    ATLAS is included for an AI system (``ai_system.is_ai_system``): an AI
    application type, or any AI pattern selected or detected.
    """

    domains = ["enterprise"]
    if app_type in _MOBILE_APP_TYPES:
        domains.append("mobile")
    if app_type in _ICS_APP_TYPES:
        domains.append("ics")
    return domains, is_ai_system(app_type, patterns)


def catalog_for_app_type(app_type: str, patterns: Iterable[str] = ()) -> list[CatalogEntry]:
    """The catalog a run validates technique ids against: the ATT&CK domains
    for the app type, plus ATLAS for an AI system. The ATT&CK pick reads only
    its ATT&CK entries and the ATLAS pick only its ATLAS entries."""
    domains, include_atlas = domains_for_app_type(app_type, patterns)
    return build_catalog(domains, include_atlas=include_atlas)
