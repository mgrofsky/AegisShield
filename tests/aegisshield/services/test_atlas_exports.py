"""The MITRE ATLAS block in every export, the fixed ATLAS links, the review
flag for the new field, and an older record without the field."""

from __future__ import annotations

import copy
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from aegisshield.pipeline import catalog_service
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY, STATUS_TEXT
from aegisshield.pipeline.formatting_service import (
    atlas_mapping_export,
    atlas_mapping_to_markdown,
    mitre_data_to_markdown,
)
from aegisshield.pipeline.mitre_links import (
    atlas_case_study_url,
    atlas_mitigation_url,
    atlas_technique_url,
    attack_url,
    technique_url,
)
from aegisshield.services import export_service, report_service
from aegisshield.services.output_checks import review_flags
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import threat_model_view as view
from aegisshield.ui.tm_detail import mitre_url
from tests.aegisshield.pipeline import non_ai_pin
from tests.aegisshield.pipeline.test_atlas_flow import AI_PROFILE, _run

EXPORTS = Path(__file__).parent / "fixtures" / "exports"
TECHNIQUE_LINK = re.compile(r"https://atlas\.mitre\.org/techniques/AML\.T\d{4}(?:\.\d{3})?\b")


@lru_cache(maxsize=1)
def _ai() -> tuple[tuple[str, Any], ...]:
    _llm, result, _sink = _run(AI_PROFILE, agentic=False)
    return tuple(result.items())


def ai_result() -> dict[str, Any]:
    return copy.deepcopy(dict(_ai()))


def _first_mapped(result: dict[str, Any]) -> dict[str, Any]:
    return next(r for r in result[ATLAS_RESULT_KEY]["threats"] if r["technique"])


def test_the_url_forms_confirmed_for_each_kind_of_id() -> None:
    assert atlas_technique_url("AML.T0051") == "https://atlas.mitre.org/techniques/AML.T0051"
    assert atlas_technique_url(" AML.T0051.000 ") == "https://atlas.mitre.org/techniques/AML.T0051.000"
    assert atlas_mitigation_url("AML.M0015") == "https://atlas.mitre.org/mitigations/AML.M0015"
    assert atlas_case_study_url("AML.CS0043") == "https://atlas.mitre.org/studies/AML.CS0043"
    assert attack_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"
    assert technique_url("AML.T0051") == mitre_url("AML.T0051") == atlas_technique_url("AML.T0051")
    assert mitre_url("T1078") == "https://attack.mitre.org/techniques/T1078/"
    for bad in ("AML.T0051/../x", "AML.M0015.1", "AML.CS43", "aml.t0051", None, "AML.T0051.0000", "T1078/x"):
        assert technique_url(bad) is None
        assert atlas_mitigation_url(bad) is None and atlas_case_study_url(bad) is None


def test_the_catalog_text_uses_the_same_page_forms() -> None:
    """The bundled ATLAS text links to its own pages in these forms."""
    text = json.dumps(catalog_service._atlas_data())
    assert "(/techniques/AML.T0051)" in text and "(/mitigations/AML.M" in text
    assert re.search(r"\(/techniques/AML\.T\d{4}\.\d{3}\)", text)


def test_an_atlas_id_in_the_attack_markdown_links_to_atlas() -> None:
    markdown = mitre_data_to_markdown([{"threat": {"ID": "TC-T01", "Threat Type": "Tampering"},
                                        "mitre_techniques": [{"technique_id": "AML.T0051", "name": "LLM Prompt Injection",
                                                              "id": "AML.T0051"}]}])
    assert "[View on ATLAS](https://atlas.mitre.org/techniques/AML.T0051)" in markdown
    assert "attack.mitre.org/techniques/AML" not in markdown


def test_markdown_html_pdf_and_json_carry_the_block_with_links() -> None:
    result = ai_result()
    row = _first_mapped(result)
    tid = row["technique"]["technique_id"]
    record = Workspace().add(RecordKind.THREAT_MODELS, "AI", {**result, "profile": AI_PROFILE,
                                                               "description": non_ai_pin.DESCRIPTION})
    bundle = view.bundle_markdown(record)
    assert "## MITRE ATLAS" in bundle and f"]({atlas_technique_url(tid)})" in bundle
    html = export_service.to_html_report(result, AI_PROFILE, non_ai_pin.DESCRIPTION)
    pdf_html = report_service.build_report_html(result, AI_PROFILE, non_ai_pin.DESCRIPTION)
    for page in (html, pdf_html):
        assert "<h2>MITRE ATLAS</h2>" in page
        assert f'href="{atlas_technique_url(tid)}"' in page
        if row["mitigations"]:
            assert f'href="{atlas_mitigation_url(row["mitigations"][0]["id"])}"' in page
        assert "attack.mitre.org/techniques/AML" not in page
    block = export_service.to_json_report(result, AI_PROFILE, "")[ATLAS_RESULT_KEY]
    first = next(t for t in block["threats"] if t["technique"])
    assert first["technique"]["url"] == atlas_technique_url(first["technique"]["id"])
    assert all(m["url"] == atlas_mitigation_url(m["id"]) for m in first["mitigations"])
    assert all(c["url"] == atlas_case_study_url(c["id"]) for c in first["case_studies"])
    assert block["atlas_version"] == catalog_service.atlas_version()


def test_sarif_keeps_its_shape_and_points_each_result_at_its_atlas_technique() -> None:
    result = ai_result()
    sarif = export_service.to_sarif(result, AI_PROFILE)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["rules"]
    (taxonomy,) = run["taxonomies"]
    assert taxonomy["name"] == "MITRE ATLAS" and taxonomy["version"] == catalog_service.atlas_version()
    taxa = {t["id"]: t for t in taxonomy["taxa"]}
    assert all(TECHNIQUE_LINK.fullmatch(t["helpUri"]) for t in taxa.values())
    for res in run["results"]:
        (ref,) = res["taxa"]
        assert ref["id"] in taxa and ref["toolComponent"] == {"name": "MITRE ATLAS"}
    assert all(not r["id"].startswith("AML.") for r in run["tool"]["driver"]["rules"])
    json.dumps(sarif)


def test_catalog_text_is_shown_not_stored_text_and_unknown_ids_are_dropped() -> None:
    result = ai_result()
    row = _first_mapped(result)
    row["technique"]["name"] = "[evil](https://evil.example/x)"
    row["threat_type"] = "<b>[x](https://evil.example)</b>"
    row["mitigations"].append({"id": "AML.M9999", "name": "Fake"})
    row["threat_id"] = "not an id"
    markdown = atlas_mapping_to_markdown(result[ATLAS_RESULT_KEY])
    assert "](https://evil" not in markdown and "AML.M9999" not in markdown
    assert "### - - " in markdown
    html = export_service.to_html_report(result, AI_PROFILE, "")
    assert 'href="https://evil' not in html
    exported = atlas_mapping_export(result[ATLAS_RESULT_KEY])
    assert exported is not None
    assert all(m["id"] != "AML.M9999" for t in exported["threats"] if t["technique"] for m in t["mitigations"])


def test_each_status_is_said_plainly() -> None:
    rows = [{"threat_id": f"TC-T0{i}", "threat_type": "Tampering", "status": status, "technique": None}
            for i, status in enumerate(STATUS_TEXT, 1) if status != "mapped"]
    rows.append({"threat_id": "TC-T09", "status": "mapped", "technique": {"technique_id": "AML.T9999"}})
    markdown = atlas_mapping_to_markdown({"atlas_version": "2026.10", "attack_version": "x", "call": "failed",
                                          "threats": rows})
    for status, text in STATUS_TEXT.items():
        if status != "mapped":
            assert text in markdown
    assert "did not finish" in markdown and "ATT&CK unknown" in markdown
    assert "AML.T9999" not in markdown
    exported = atlas_mapping_export({"call": "odd", "threats": [{"status": "odd"}]})
    assert exported == {"atlas_version": "unknown", "attack_version": "unknown", "call": "unknown",
                        "threats": [{"threat_id": "", "threat_type": "", "status": "unknown", "technique": None}]}


def test_a_parent_techniques_links_are_labeled_as_such() -> None:
    sub = next(e.technique_id for e in catalog_service.load_atlas_entries()
               if e.technique_id.count(".") == 2 and not catalog_service.atlas_mitigations_for(e.technique_id)
               and catalog_service.atlas_mitigations_for(e.technique_id.rsplit(".", 1)[0]))
    from aegisshield.pipeline.atlas_service import technique_links

    row = {"threat_id": "TC-T01", "threat_type": "Tampering", "status": "mapped",
           "technique": {"technique_id": sub}, **technique_links(sub)}
    markdown = atlas_mapping_to_markdown({"threats": [row]})
    assert f"listed for the parent technique {sub.rsplit('.', 1)[0]}" in markdown


def test_review_flags_an_atlas_id_outside_the_catalog_in_the_new_field() -> None:
    result = ai_result()
    row = _first_mapped(result)
    row["technique"]["technique_id"] = "AML.T9999"
    flags = review_flags(result, profile=AI_PROFILE, addons=[])
    hits = [f for f in flags if f["code"] == "unsupported_technique" and f["field"] == "atlas_mapping"]
    assert len(hits) == 1 and "AML.T9999" in hits[0]["sentence"] and hits[0]["threat_id"] == row["threat_id"]


def test_model_text_naming_a_real_atlas_id_is_not_flagged_for_an_ai_system() -> None:
    result = ai_result()
    result["mitigations_markdown"] += "\nSee AML.T0051 for prompt injection."
    flags = review_flags(result, profile=AI_PROFILE, addons=[])
    assert not [f for f in flags if f["code"] == "unsupported_technique"]
    result["detected_patterns"] = []
    plain = review_flags(result, profile=non_ai_pin.PROFILE, addons=[])
    assert [f for f in plain if f["code"] == "unsupported_technique" and "AML.T0051" in f["sentence"]]


@pytest.fixture
def old_record() -> dict[str, Any]:
    """A saved job result from before ATLAS mapping (an existing fixture), for
    an AI application type, as an older or imported record would hold it."""
    request = json.loads((EXPORTS / "request.json").read_text(encoding="utf-8"))
    result = json.loads((EXPORTS / "job_result.json").read_text(encoding="utf-8"))
    return {**result, "profile": {**request["app_profile"], "app_type": "AI/ML Systems"},
            "description": request["app_description"]}


def test_an_older_record_without_the_field_loads_and_renders_as_before(old_record: dict[str, Any]) -> None:
    assert ATLAS_RESULT_KEY not in old_record
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", old_record)
    restored = Workspace.from_json(ws.to_json())
    loaded = restored.get(RecordKind.THREAT_MODELS, record.id)
    assert loaded is not None and loaded.payload == record.payload
    assert view.atlas_rows(loaded.payload) == [] and view.count_atlas_techniques(loaded.payload) == 0
    assert "MITRE ATLAS" not in view.bundle_markdown(loaded).replace("MITRE ATT&CK and ATLAS", "")
    profile = loaded.payload["profile"]
    assert "<h2>MITRE ATLAS</h2>" not in export_service.to_html_report(loaded.payload, profile, "")
    assert "<h2>MITRE ATLAS</h2>" not in report_service.build_report_html(loaded.payload, profile, "")
    assert ATLAS_RESULT_KEY not in export_service.to_json_report(loaded.payload, profile, "")
    assert "taxonomies" not in export_service.to_sarif(loaded.payload, profile)["runs"][0]
