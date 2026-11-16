"""The ATLAS table: one entry per offered probe, each id in the app's catalog."""

from __future__ import annotations

from aegisshield.aiscan import probes, taxonomy
from aegisshield.pipeline.catalog_service import load_atlas_entries


def test_every_offered_probe_has_at_least_one_reasoned_atlas_reference():
    assert set(taxonomy.ATLAS_BY_PROBE) == {p.id for p in probes.PROBES}
    assert len(taxonomy.ATLAS_BY_PROBE) == 19
    for refs in taxonomy.ATLAS_BY_PROBE.values():
        assert refs and len({r.id for r in refs}) == len(refs)
        for ref in refs:
            assert ref.id.startswith("AML.T") and ref.id in taxonomy.ATLAS_NAMES
            assert ref.reason and "\n" not in ref.reason and len(ref.reason) <= 100
            assert ref.url == f"https://atlas.mitre.org/techniques/{ref.id}"


def test_names_come_from_the_catalog():
    by_id = {e.technique_id: e.name for e in load_atlas_entries()}
    assert taxonomy.ATLAS_NAMES["AML.T0077"] == by_id["AML.T0077"] == "LLM Response Rendering"
    assert taxonomy.ATLAS_NAMES["AML.T0051.001"] == "LLM Prompt Injection: Indirect"
    assert taxonomy.ATLAS_NAMES["AML.T0068"] == "LLM Prompt Obfuscation"


def test_the_record_form_holds_plain_values():
    assert taxonomy.atlas_record("encoding.InjectBase64") == [
        {"id": "AML.T0051.000", "name": "LLM Prompt Injection: Direct",
         "reason": "The message hides its instruction in base64 for the model to decode."},
        {"id": "AML.T0068", "name": "LLM Prompt Obfuscation",
         "reason": "The instruction is encoded so a filter reading plain text misses it."}]
    assert taxonomy.atlas_record("not.AProbe") == []


def test_every_id_is_in_the_apps_atlas_catalog():
    catalog = {e.technique_id for e in load_atlas_entries()}
    used = {ref.id for refs in taxonomy.ATLAS_BY_PROBE.values() for ref in refs}
    assert used <= catalog, sorted(used - catalog)
    assert used == set(taxonomy.ATLAS_NAMES)
