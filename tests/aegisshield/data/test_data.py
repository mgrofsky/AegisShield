import hashlib
import json

import pytest

from aegisshield.data import data_path, mitre_data_dir

# SHA-256 of the pinned MITRE ATT&CK 20.1 bundles and the converted ATLAS
# 2026.10 file, so a changed file fails the test. tools/refresh_mitre.py
# writes these files; MITRE_ATTACK_DATA/SOURCE.md and
# aegisshield/data/atlas/SOURCE.md record where they came from.
MITRE_SHA256 = {
    "enterprise-attack.json": "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5",
    "ics-attack.json": "3f6448369f9135ade84ff6437479441530d0b262f910dca991879a7146b524ff",
    "mobile-attack.json": "632e2ec40848394f9873a7a3485fc32f92b861a4e7271f7e88e0cb02f11bb6af",
}
ATLAS_SHA256 = ("atlas-2026-10.json", "46e9f17cbeffbce48f770cb4d9ac18b35531cc08eaf0ab72bc74f9b7fc7946f1")


@pytest.mark.parametrize(
    "parts",
    [
        ("atlas", "atlas-2026-10.json"),
        ("nist", "csf-2.0.json"),
        ("regulations", "eu-ai-act-2026-graph.json"),
        ("threat_cards", "owasp_crosswalk.json"),
        ("tech_cpe_map.json",),
    ],
)
def test_json_data_present_and_parses(parts):
    path = data_path(*parts)
    assert path.is_file()
    json.loads(path.read_text(encoding="utf-8"))


def test_threat_cards_markdown():
    assert data_path("threat_cards", "owasp_llm_top_10.md").is_file()
    assert data_path("threat_cards", "owasp_agentic.md").is_file()


def test_data_path_stays_inside():
    with pytest.raises(ValueError):
        data_path("..", "config.py")


def test_mitre_bundles_match_source():
    directory = mitre_data_dir()
    for name, digest in MITRE_SHA256.items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest


def test_atlas_file_matches_source():
    name, digest = ATLAS_SHA256
    assert hashlib.sha256(data_path("atlas", name).read_bytes()).hexdigest() == digest
    assert sorted(p.name for p in data_path("atlas").glob("*.json")) == [name]
