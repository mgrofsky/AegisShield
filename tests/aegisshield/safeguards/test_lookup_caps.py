"""NVD and OTX text is clipped, with a visible note, before it is screened,
so no screened lookup text is large enough for the retrieved-content check
to approach its time limit."""

from __future__ import annotations

import pytest

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import workflow_service
from aegisshield.safeguards import Safeguards
from tests.aegisshield.safeguards import harness


def _screened(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every (source, text) the run screens."""
    seen: list[tuple[str, str]] = []
    real = Safeguards.screen

    def screen(self: Safeguards, source: object, text: str) -> str:
        seen.append((str(getattr(source, "value", source)), text))
        return real(self, source, text)  # type: ignore[arg-type]

    monkeypatch.setattr(Safeguards, "screen", screen)
    return seen


def test_long_lookup_text_is_clipped_with_a_note_before_screening(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups = harness.Lookups().install(monkeypatch)
    lookups.cve_text = "A flaw in {product} ({cve}). " + "Details of the flaw. " * 20_000
    lookups.pulses[0]["description"] = "Skimmer campaign. " * 20_000
    seen = _screened(monkeypatch)
    result = harness.run(harness.request(), llm=MockLLM(), safeguards=Safeguards.from_settings(Settings()))
    nvd = [t for s, t in seen if s == "lookup"]
    otx = [t for s, t in seen if s == "threat_intel"]
    assert nvd and otx
    cap = workflow_service.LOOKUP_TEXT_MAX_CHARS
    for text in nvd:
        assert len(text) <= cap + 80 and text.endswith(workflow_service.NVD_CLIPPED_NOTE)
    for text in otx:
        assert len(text) <= cap + 80 and text.endswith(workflow_service.OTX_CLIPPED_NOTE)
    # The sections shown with the result are the same clipped text.
    assert workflow_service.OTX_CLIPPED_NOTE in result["otx_data_markdown"]
    assert workflow_service.NVD_CLIPPED_NOTE in result["nvd_vulnerabilities_markdown"]


def test_ordinary_lookup_text_is_not_clipped(monkeypatch: pytest.MonkeyPatch) -> None:
    harness.Lookups().install(monkeypatch)
    seen = _screened(monkeypatch)
    harness.run(harness.request(), llm=MockLLM(), safeguards=Safeguards.from_settings(Settings()))
    texts = [t for s, t in seen if s in ("lookup", "threat_intel")]
    assert texts and not any("cut at" in t for t in texts)


def test_clip_cuts_at_a_line_end_or_at_the_cap() -> None:
    cap = workflow_service.LOOKUP_TEXT_MAX_CHARS
    clip = workflow_service.clip_lookup_text
    assert clip("short", "[n]") == "short"
    assert clip("x" * (cap + 5), "[n]") == "x" * cap + "\n[n]"
    assert clip("a\n" + "x" * cap, "[n]") == "a\n[n]"
