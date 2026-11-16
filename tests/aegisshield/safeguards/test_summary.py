"""The words for a safeguards record and review flags, the blocks that show
them, and the exports that carry them. Every value from a record is escaped."""

from __future__ import annotations

from typing import Any

import pytest
import streamlit as st

from aegisshield.config import get_settings
from aegisshield.safeguards import engine as engine_mod
from aegisshield.safeguards import summary
from aegisshield.services import export_service, pcap_service, policy_service, report_service
from aegisshield.ui import safeguards_view

HOSTILE = '<script>alert(1)</script> ![x](https://evil.example/?d=1) `code` [link](u)'


def _check(status: str, rail_set: str = "retrieved", **extra: Any) -> dict[str, Any]:
    return {"rail_set": rail_set, "source": extra.pop("source", "threat_intel"), "step": extra.pop("step", None),
            "status": status, "rail": "r", "reason": extra.pop("reason", "A reason."),
            "excerpt": extra.pop("excerpt", None)}


def _report(*checks: dict[str, Any], status: str = "on", simulated: bool = False) -> dict[str, Any]:
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("passed", "modified", "blocked", "not_checked")}
    return {"version": 1, "status": status, "enabled": status != "off", "strict": False,
            "engine": "NeMo Guardrails", "engine_version": "0.24.1", "simulated_model": simulated,
            "checks": list(checks), "counts": {"total": len(checks), **counts},
            "complete": counts["not_checked"] == 0}


FLAGS = [{"code": "unsupported_cve", "threat_id": "TC-S01", "field": "Scenario",
          "sentence": "Unsupported reference, review: CVE-2021-44228 is not in the NVD results supplied to this run."},
         {"code": "missing_section", "threat_id": None, "field": None, "sentence": "Something <b>bold</b>."}]


def test_each_state_reads_exactly() -> None:
    assert summary.summarize(None).headline == summary.NO_RECORD
    assert summary.summarize(_report(status="off")).headline.startswith("Safeguards were off")
    clean = summary.summarize(_report(_check("passed"), _check("passed", "output", step="model call 1 (text)")))
    assert clean.quiet and clean.tone == "ok"
    assert clean.headline == "Safeguards ran 2 checks; nothing was changed or withheld."
    unavailable = summary.summarize(_report(_check("not_checked", reason="NeMo Guardrails is not installed."),
                                            status="unavailable"))
    assert unavailable.headline.startswith("Safeguards were unavailable") and not unavailable.quiet
    assert unavailable.not_checked == ["1 of 1 checks could not run: NeMo Guardrails is not installed. "
                                       "This result is not fully checked."]
    mixed = summary.summarize(_report(
        _check("modified", excerpt="Ignore previous &quot;x&quot;"),
        _check("blocked", "output", step="model call 2 (JSON)", reason="Leak."),
        _check("modified", "output", step="model call 3 (text)", reason="Removed a key."),
        _check("modified", "output", step="model call 4 (text)", reason="Removed a key."),
        _check("not_checked", reason="The check raised an error."),
        _check("passed", excerpt="quoted note"),
        simulated=True,
    ))
    assert mixed.headline == "Safeguards ran 6 checks: 3 changed, 1 withheld, 1 not checked."
    assert mixed.changed[0] == ('Threat intelligence (retrieved-content check): A reason. '
                                'Excerpt: "Ignore previous "x""')
    assert mixed.changed[1] == "2 model answers (answer check): Removed a key."
    assert mixed.withheld == ["1 model answer (answer check): Leak."]
    assert summary.SIMULATED_NOTE in mixed.notes
    assert any("quoted note" in n for n in mixed.notes)


def test_markdown_and_html_escape_everything() -> None:
    report = _report(_check("modified", excerpt=HOSTILE, reason=HOSTILE))
    md = summary.as_markdown(report, FLAGS)
    assert "<script>" not in md and "![x](" not in md and "\\<script\\>" in md
    assert "## Review flags" in md and "TC\\-S01" not in md and "TC-S01, Scenario" in md
    page = summary.as_html(report, FLAGS)
    assert "<script>" not in page and "&lt;script&gt;" in page and "<b>bold</b>" not in page
    assert "Review flags: 2 items need review." in page
    assert "## Review flags" not in summary.as_markdown(report, FLAGS, with_flags=False)
    assert "Review flags" not in summary.as_html(report, with_flags=False)
    assert summary.flags_headline([]) == "Review flags: none."
    assert summary.flags_headline(FLAGS[:1]) == "Review flags: 1 item needs review."
    assert summary.flag_items([{"sentence": ""}, "x", FLAGS[1]]) == [(None, None, "Something <b>bold</b>.")]


@pytest.fixture
def drawn(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    out: list[str] = []
    monkeypatch.setattr(st, "html", lambda body, **_: out.append(str(body)))
    monkeypatch.setattr(st, "caption", lambda body, **_: out.append(str(body)))
    return out


def test_the_blocks(drawn: list[str]) -> None:
    safeguards_view.render_safeguards(_report(_check("passed")), key="t")
    assert len(drawn) == 1 and "nothing was changed or withheld" in drawn[0]
    drawn.clear()
    safeguards_view.render_safeguards(_report(_check("modified", excerpt=HOSTILE)), key="t")
    joined = "".join(drawn)
    assert "Changed" in joined and "<script>alert" not in joined and "&lt;script&gt;" in joined
    drawn.clear()
    safeguards_view.render_review_flags([], key="t")
    assert drawn == [f'<p class="sg-quiet">{"Review flags: none. " + summary.FLAGS_NOTE}</p>']
    drawn.clear()
    safeguards_view.render_review_flags(FLAGS, key="t", threat_titles={"TC-S01": "x" * 80})
    joined = "".join(drawn)
    assert f'href="#{safeguards_view.threat_anchor("TC-S01")}"' in joined
    assert "x" * 45 + "..." in joined and "<b>bold</b>" not in joined
    assert safeguards_view.threat_anchor('TC-S01"><x') == "tm-threat-TC-S01x"


@pytest.mark.parametrize("env,word", [({}, "On"), ({"AEGIS_SAFEGUARDS": "off"}, "Off")])
def test_the_settings_status(env: dict[str, str], word: str, drawn: list[str]) -> None:
    safeguards_view.render_status(get_settings(env))
    joined = "".join(drawn)
    assert f">{word}<" in joined and "0.24.1" in joined
    if word == "Off":
        assert "AEGIS_SAFEGUARDS" in joined


def test_the_settings_status_when_unavailable(drawn: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "nemo_available", lambda: False)
    monkeypatch.setattr(engine_mod, "nemo_version", lambda: None)
    safeguards_view.render_status(get_settings({}))
    joined = "".join(drawn)
    assert ">Unavailable<" in joined and "not installed" in joined


def test_every_export_carries_the_summary() -> None:
    report = _report(_check("modified", reason="Removed for review."))
    result = {"threat_model": [], "safeguards": report, "review_flags": FLAGS}
    data = export_service.to_json_report(result, {}, "d")
    assert data["safeguards"] == report and data["review_flags"] == FLAGS
    assert "Removed for review." in data["safeguards_summary"]
    assert "Removed for review." in export_service.to_html_report(result, {}, "d")
    assert "Removed for review." in report_service.build_report_html(result, {}, "d", logo_base64="")
    assert "Safeguards ran 1 check:" in pcap_service.render_markdown_report({"safeguards": report})
    policy = {"title": "P", "body_markdown": "Body.", "safeguards": report}
    assert "Removed for review." in policy_service.build_policy_html(policy)
    assert policy_service.policy_markdown_export(policy).startswith("Body.\n\n---\n\n## Safeguards")
    assert policy_service.policy_markdown_export({"body_markdown": "Body."}) == "Body."
    assert export_service.to_json_report({}, {}, "d")["safeguards"] is None
