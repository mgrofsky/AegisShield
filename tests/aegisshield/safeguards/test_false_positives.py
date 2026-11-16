"""The false-positive set: legitimate security text passes with zero blocks
and zero modifications, through the real entry points.

A check that fires on the topic is a defect. See ``corpus`` for the items
and why each one is here.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.safeguards import Safeguards, Source, detect
from aegisshield.services import policy_service
from tests.aegisshield.safeguards import corpus, harness

ALL_SOURCES = list(Source)


def _clean(report: dict[str, Any]) -> None:
    counts = harness.statuses(report)
    bad = [c for c in report["checks"] if c["status"] != "passed"]
    # A passed check may carry a note (a quoted instruction left as it is);
    # nothing may be changed, withheld, or left unchecked.
    assert counts["modified"] == counts["blocked"] == counts["not_checked"] == 0, bad


def _screen_everywhere(text: str) -> None:
    """``text`` passes unchanged as every source and as a model answer."""
    sg = Safeguards.from_settings(Settings())
    for source in ALL_SOURCES:
        assert sg.screen(source, text) == text, source
    status, answer, _ = sg.check_answer(step="t", system="System prompt for the step under test.",
                                        user="", answer=text)
    assert answer == text
    _clean(sg.report())
    assert detect.demands_in(text) == []


@pytest.mark.parametrize("text", corpus.AI_APP_DESCRIPTIONS, ids=lambda t: t[:30])
def test_ai_application_descriptions_quoting_attacks_pass(text: str) -> None:
    _screen_everywhere(text)


@pytest.mark.parametrize("text", corpus.LOOKALIKES, ids=lambda t: t[:30])
def test_sentences_shaped_like_the_patterns_pass(text: str) -> None:
    _screen_everywhere(text)


def test_a_description_that_discusses_injection_and_leakage_passes() -> None:
    _screen_everywhere(corpus.THREAT_DISCUSSION)


@pytest.mark.parametrize("name,text", corpus.reference_texts(), ids=lambda v: v if len(v) < 40 else "")
def test_the_apps_own_atlas_and_owasp_reference_text_passes(name: str, text: str) -> None:
    _screen_everywhere(text)


@pytest.mark.parametrize("cve,text", corpus.CVE_DESCRIPTIONS, ids=lambda v: v if v.startswith("CVE") else "")
def test_real_cve_descriptions_that_mention_injection_pass(cve: str, text: str) -> None:
    _screen_everywhere(text)


def test_a_policy_telling_staff_not_to_share_credentials_passes() -> None:
    _screen_everywhere(corpus.CREDENTIALS_POLICY)


class _PolicyLLM(MockLLM):
    def chat_text(self, **kwargs: Any) -> str:
        return corpus.CREDENTIALS_POLICY


def test_the_credentials_policy_as_a_generated_policy_passes() -> None:
    profile = {"legal_name": "Northwind Outfitters Inc.", "industry": "Retail and e-commerce",
               "employee_count": 240, "leadership": [{"role": "CISO", "name": "Sam Patel"}],
               "compliance_drivers": ["PCI DSS"], "regulatory_notes": "Never share credentials."}
    result = policy_service.generate_policy("information_security_policy", profile,
                                            llm=_PolicyLLM(), settings=Settings())
    assert result["body_markdown"] == corpus.CREDENTIALS_POLICY
    _clean(result["safeguards"])
    assert harness.checks(result["safeguards"], "output")


@pytest.mark.parametrize("name,text", corpus.batch_descriptions(), ids=lambda v: v if v.endswith(".json") else "")
def test_every_batch_input_runs_as_a_description_with_nothing_found(
    name: str, text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.Lookups().install(monkeypatch)
    result = harness.run(harness.request(text[:20_000]))
    report = result["safeguards"]
    _clean(report)
    assert report["status"] == "on" and report["complete"] is True
    assert result["threat_model"]


def test_a_pasted_system_prompt_is_fenced_not_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hard case: an instruction to a model inside the visitor's own
    description. It is fenced as data with a finding, and the run goes on."""
    harness.Lookups().install(monkeypatch)
    result = harness.run(harness.request(corpus.PASTED_SYSTEM_PROMPT))
    report = result["safeguards"]
    [fenced] = [c for c in report["checks"] if c["status"] == "modified"]
    assert fenced["rail_set"] == "input" and fenced["source"] == "description"
    assert "Fenced as data" in fenced["reason"]
    assert report["counts"]["blocked"] == 0
    assert result["threat_model"]


@pytest.mark.parametrize("text", [
    "", "   ", "Price is $5 and {braces} stay {0} and %s and \\n", "trailing space   \n\n",
    "Line one\r\nLine two\ttabbed", "unicode é中  separators",
])
def test_text_comes_back_byte_identical(text: str) -> None:
    sg = Safeguards.from_settings(Settings())
    for source in ALL_SOURCES:
        assert sg.screen(source, text) == text
    if text.strip():
        assert sg.check_answer(step="t", system="", user="", answer=text)[1] == text
    assert all(c["status"] == "passed" for c in sg.report()["checks"])
