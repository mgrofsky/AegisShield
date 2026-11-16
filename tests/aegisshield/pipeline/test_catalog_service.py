"""The ATT&CK and ATLAS catalog: parsing, the pinned files, ids, and routing by app type."""

from __future__ import annotations

import pytest

from aegisshield.pipeline.catalog_service import (
    AtlasCaseStudy,
    AtlasMitigation,
    AtlasTactic,
    CatalogEntry,
    _atlas_to_entry,
    _attack_pattern_to_entry,
    atlas_case_studies,
    atlas_case_studies_for,
    atlas_mitigations,
    atlas_mitigations_for,
    atlas_tactics,
    atlas_version,
    attack_version,
    build_catalog,
    catalog_for_app_type,
    domains_for_app_type,
    index_by_id,
    load_atlas_entries,
    load_attack_entries,
    validate_id,
)


def test_attack_pattern_extracts_technique_id_and_tactic() -> None:
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--abc",
        "name": "Phishing",
        "description": "Initial access via deceptive email.",
        "kill_chain_phases": [{"phase_name": "initial-access"}],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1566"}
        ],
    }
    entry = _attack_pattern_to_entry(obj, "enterprise")
    assert entry is not None
    assert entry.technique_id == "T1566"
    assert entry.stix_id == "attack-pattern--abc"
    assert entry.tactic == "Initial Access"
    assert entry.framework == "ATT&CK"


def test_attack_pattern_skips_revoked_or_deprecated() -> None:
    revoked = {"type": "attack-pattern", "revoked": True}
    deprecated = {"type": "attack-pattern", "x_mitre_deprecated": True}
    not_attack = {"type": "intrusion-set"}
    no_ext_id = {"type": "attack-pattern", "external_references": []}
    for obj in (revoked, deprecated, not_attack, no_ext_id):
        assert _attack_pattern_to_entry(obj, "enterprise") is None


def test_atlas_to_entry_minimal() -> None:
    obj = {"id": "AML.T0051", "name": "LLM Prompt Injection", "description": "x", "parent": None,
           "tactics": [{"id": "AML.TA0005", "name": "Execution"}, {"id": "AML.TA0004", "name": "Initial Access"}]}
    entry = _atlas_to_entry(obj)
    assert entry.framework == "ATLAS"
    assert entry.technique_id == "AML.T0051"
    assert entry.stix_id is None
    assert entry.tactic == "Execution"  # the first tactic, as for ATT&CK


def test_load_atlas_entries_loads_committed_pin() -> None:
    entries = load_atlas_entries()
    assert entries, "ATLAS pin must be present"
    ids = {e.technique_id for e in entries}
    # Spot-check a few well-known entries that should never disappear silently.
    assert "AML.T0051" in ids  # LLM Prompt Injection
    assert "AML.T0051.000" in ids  # its Direct sub-technique
    assert "AML.T0020" in ids  # Training Data Poisoning
    assert all(e.framework == "ATLAS" and e.domain == "atlas" for e in entries)
    assert all(e.tactic != "Unknown" and e.description for e in entries)


def test_index_by_id_indexes_both_aliases() -> None:
    entries = [
        CatalogEntry(
            framework="ATT&CK",
            domain="enterprise",
            technique_id="T1059",
            stix_id="attack-pattern--xyz",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            description="...",
        )
    ]
    index = index_by_id(entries)
    assert index["T1059"].name.startswith("Command")
    assert index["attack-pattern--xyz"].technique_id == "T1059"


def test_validate_id_rejects_unknown_and_blank() -> None:
    entries = [
        CatalogEntry(
            framework="ATLAS",
            domain="atlas",
            technique_id="AML.T0051",
            stix_id=None,
            name="LLM Prompt Injection",
            tactic="Initial Access",
            description="x",
        )
    ]
    index = index_by_id(entries)
    assert validate_id(index, "AML.T0051") is not None
    assert validate_id(index, "T9999") is None
    assert validate_id(index, "") is None
    assert validate_id(index, "   ") is None
    assert validate_id(index, None) is None  # type: ignore[arg-type]


def test_domains_for_app_type_routes_correctly() -> None:
    assert domains_for_app_type("Web application") == (["enterprise"], False)
    assert domains_for_app_type("Mobile application") == (["enterprise", "mobile"], False)
    assert domains_for_app_type("ICS or SCADA System") == (["enterprise", "ics"], False)
    assert domains_for_app_type("AI/ML Systems") == (["enterprise"], True)


def test_catalog_for_app_type_includes_atlas_for_ai() -> None:
    catalog = catalog_for_app_type("AI/ML Systems")
    frameworks = {e.framework for e in catalog}
    assert "ATT&CK" in frameworks
    assert "ATLAS" in frameworks


def test_build_catalog_smoke() -> None:
    # Loads the full pinned dataset; should be hundreds of entries.
    catalog = build_catalog(["enterprise"], include_atlas=False)
    assert len(catalog) > 100
    assert all(e.technique_id.startswith("T") for e in catalog)


def test_versions_are_read_from_the_data() -> None:
    assert attack_version() == "20.1"
    assert atlas_version() == "2026.10"


@pytest.mark.parametrize(("domain", "count"), [("enterprise", 706), ("ics", 104), ("mobile", 125)])
def test_attack_counts_and_every_live_technique_has_an_id_and_tactic(domain: str, count: int) -> None:
    entries = load_attack_entries([domain])
    assert len(entries) == count
    assert all(e.technique_id.startswith("T") and e.tactic != "Unknown" for e in entries)


def test_attack_version_names_each_domain_when_they_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.pipeline import catalog_service

    versions = {"enterprise": "20.1", "mobile": "20.1", "ics": "19.2"}
    monkeypatch.setattr(catalog_service, "_domain_version", versions.__getitem__)
    assert attack_version() == "enterprise 20.1, mobile 20.1, ics 19.2"


def test_atlas_counts() -> None:
    entries = load_atlas_entries()
    subs = [e for e in entries if "." in e.technique_id.removeprefix("AML.")]
    assert (len(entries) - len(subs), len(subs)) == (129, 92)
    assert len(atlas_tactics()) == 16
    assert len(atlas_mitigations()) == 44
    assert len(atlas_case_studies()) == 77


def test_atlas_references_only_ids_that_exist() -> None:
    ids = {e.technique_id for e in load_atlas_entries()}
    for mitigation in atlas_mitigations():
        assert mitigation.technique_ids and set(mitigation.technique_ids) <= ids, mitigation.id
    for case in atlas_case_studies():
        assert case.technique_ids and set(case.technique_ids) <= ids, case.id
    for entry in load_atlas_entries():
        if "." in entry.technique_id.removeprefix("AML."):
            assert entry.technique_id.rsplit(".", 1)[0] in ids


def test_atlas_accessors() -> None:
    tactics = atlas_tactics()
    assert all(isinstance(t, AtlasTactic) and t.id.startswith("AML.TA") and t.name for t in tactics)
    mitigations = atlas_mitigations_for("AML.T0051")
    assert mitigations and all(isinstance(m, AtlasMitigation) for m in mitigations)
    assert all("AML.T0051" in m.technique_ids for m in mitigations)
    cases = atlas_case_studies_for("AML.T0051.000")
    assert cases and all(isinstance(c, AtlasCaseStudy) and c.summary for c in cases)
    assert all("AML.T0051.000" in c.technique_ids for c in cases)
    assert atlas_mitigations_for("AML.T9999") == ()
    assert atlas_case_studies_for("T1059") == ()
    assert atlas_mitigations_for("AML.T0051") is atlas_mitigations_for("AML.T0051")  # cached
