"""Wording and character rules for the policy and packet capture modules.

Files are ASCII (no em or en dashes, no invisible characters), and the system
prompts name no compliance framework: a draft cites one only when the visitor
selects it as a compliance driver.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisshield.services import org_profile, pcap_service, policy_service

ROOT = Path(__file__).resolve().parents[3]
FILES = [
    "aegisshield/services/org_profile.py",
    "aegisshield/services/policy_catalog.py",
    "aegisshield/services/policy_service.py",
    "aegisshield/services/pcap_service.py",
    "tests/aegisshield/services/fake_tshark.py",
    "tests/aegisshield/services/test_org_profile.py",
    "tests/aegisshield/services/test_policy_service.py",
    "tests/aegisshield/services/test_pcap_service.py",
    "tests/aegisshield/services/test_policies_pcap_wording.py",
]
@pytest.mark.parametrize("name", FILES)
def test_files_are_ascii(name: str) -> None:
    (ROOT / name).read_text(encoding="ascii")


def test_fixtures_are_ascii() -> None:
    for path in (ROOT / "tests/aegisshield/services/fixtures/tshark").iterdir():
        path.read_text(encoding="ascii")


@pytest.mark.parametrize("prompt", [policy_service.SYSTEM_PROMPT, pcap_service.ANALYSIS_SYSTEM_PROMPT])
def test_system_prompts_name_no_compliance_framework(prompt: str) -> None:
    for driver in org_profile.KNOWN_COMPLIANCE_DRIVERS:
        assert driver not in prompt, driver
