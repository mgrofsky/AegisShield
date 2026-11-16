"""The PCAP analysis page under AppTest, with a fake tshark on PATH."""

from __future__ import annotations

import shutil

import pytest

from aegisshield.core.errors import LLMError
from aegisshield.services import pcap_service
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import pcap_data, tool_parts
from aegisshield.ui.pages import pcap_analysis as page
from tests.aegisshield.ui import pcap_fakes
from tests.aegisshield.ui.lookup_fakes import HOSTILE
from tests.aegisshield.ui.tool_helpers import (
    Gate,
    click_and_finish,
    fresh_runner,
    html_of,
    make_app,
    wait_for_jobs,
)

__all__ = ["fresh_runner"]


@pytest.fixture(autouse=True)
def fast_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    monkeypatch.setattr(tool_parts, "MOCK_STREAM_DELAY", 0.0)


@pytest.fixture
def tshark(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PATH", pcap_fakes.install(tmp_path / "bin"))
    assert shutil.which("tshark")
    return tmp_path


def _ws(at) -> Workspace:
    return at.session_state["aegis_workspace"]


@pytest.fixture
def uploaded(monkeypatch: pytest.MonkeyPatch):
    holder: dict = {}

    class Uploaded:
        def __init__(self, name: str, data: bytes) -> None:
            self.name, self._data = name, data

        def getvalue(self) -> bytes:
            return self._data

    def fake_uploader(*args, **kwargs):
        assert kwargs.get("max_upload_size") == page.MAX_UPLOAD_MB
        assert kwargs.get("type") == ["pcap", "pcapng"]
        return Uploaded(*holder["file"]) if "file" in holder else None

    import streamlit as st

    monkeypatch.setattr(st, "file_uploader", fake_uploader)
    return holder


def _analyze(at, runner, uploaded, data: bytes | None = None, name: str = "voip <call>.pcap"):
    uploaded["file"] = (name, data if data is not None else pcap_fakes.MINIMAL_PCAP.read_bytes())
    at.run()
    return click_and_finish(at, "pcap_run", runner)


def test_hidden_message_without_tshark(fresh_runner, monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    at = make_app(page.PAGE).run()
    assert not at.exception
    body = html_of(at)
    assert "PCAP analysis is not available here" in body
    assert "pcap_run" not in [b.key for b in at.button]


def test_empty_page_states_privacy_and_limits(fresh_runner, tshark, uploaded) -> None:
    at = make_app(page.PAGE).run()
    body = html_of(at)
    assert "parsed with tshark on the server running this app" in body
    assert "never the raw capture" in body and "sensitive data" in body
    assert "up to 25 MB" in body
    assert "No analyses yet" in body


def test_no_file_and_a_bad_file_are_refused_before_any_job(fresh_runner, tshark, uploaded) -> None:
    at = make_app(page.PAGE).run()
    at.button(key="pcap_run").click().run()
    assert "Choose a capture file first." in html_of(at)
    uploaded["file"] = ("notes.txt", b"hello")
    at.button(key="pcap_run").click().run()
    assert pcap_service.ERROR_EXTENSION in html_of(at).replace("&#x27;", "'")
    uploaded["file"] = ("fake.pcap", b"PK\x03\x04 not a capture")
    at.button(key="pcap_run").click().run()
    assert fresh_runner._jobs == {}


def test_full_run_saves_a_trimmed_record_once_and_shows_every_section(fresh_runner, tshark, uploaded) -> None:
    at = _analyze(make_app(page.PAGE), fresh_runner, uploaded)
    assert not at.exception
    (record,) = _ws(at).list(RecordKind.PCAP_ANALYSES)
    assert record.title == "voip <call>.pcap"
    assert "run" not in at.query_params
    assert "stored_rows" in record.payload["result"]
    body = html_of(at)
    assert "Analysis finished and saved" in body
    assert "voip &lt;call&gt;.pcap" in body
    assert "SIP auth failures" in body and "Scanner user agents" in body
    labels = [t.label for t in at.tabs]
    assert labels[:6] == ["AI analysis", "Protocols", "Conversations", "DNS", "TLS", "HTTP"]
    assert "SIP" in labels and "RTP" in labels
    assert any(m.value and "Findings" in m.value for m in at.markdown)
    assert len(at.dataframe) >= 6
    at.run()
    assert len(_ws(at).list(RecordKind.PCAP_ANALYSES)) == 1
    report = pcap_service.render_markdown_report(dict(record.payload["result"]))
    assert "voip" in report


def test_model_failure_keeps_the_summary_and_says_so(fresh_runner, tshark, uploaded, monkeypatch) -> None:
    def broken(summary, **kwargs):
        raise LLMError("down")

    monkeypatch.setattr(pcap_service, "analyze_summary", broken)
    at = _analyze(make_app(page.PAGE), fresh_runner, uploaded)
    body = html_of(at)
    assert pcap_service.ERROR_AI.replace("'", "&#x27;") in body
    assert "The parsed summary in the other tabs is complete." in body
    assert len(_ws(at).list(RecordKind.PCAP_ANALYSES)) == 1


def test_a_failed_analysis_saves_nothing(fresh_runner, tshark, uploaded, monkeypatch) -> None:
    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(pcap_service, "analyze_pcap", broken)
    at = _analyze(make_app(page.PAGE), fresh_runner, uploaded)
    assert "The analysis did not finish." in html_of(at)
    assert _ws(at).list(RecordKind.PCAP_ANALYSES) == []
    at.run()
    assert "The analysis did not finish." in html_of(at)  # stays until dismissed
    at.button(key="pcap_dismiss").click().run()
    assert "The analysis did not finish." not in html_of(at)
    assert fresh_runner._jobs == {}


def test_progress_reattach_and_cancel(fresh_runner, tshark, uploaded, monkeypatch) -> None:
    gate = Gate()

    def slow(data, filename, *, llm, settings, progress=None, on_text=None):
        progress.set({"step": 3, "total": 8, "current": "Reading RTP streams"})
        on_text("Partial <b>analysis</b>")
        progress.flush()
        gate.wait()
        return {"filename": filename}

    monkeypatch.setattr(pcap_service, "analyze_pcap", slow)
    uploaded["file"] = ("call.pcap", pcap_fakes.MINIMAL_PCAP.read_bytes())
    at = make_app(page.PAGE).run()
    at.button(key="pcap_run").click().run()
    assert gate.started.wait(5)
    at.run()
    body = html_of(at)
    assert "Analyzing call.pcap" in body and "Step 3 of 8: Reading RTP streams" in body
    at.run()
    assert "Analyzing call.pcap" in html_of(at)
    at.button(key="pcap_cancel_danger").click().run()
    assert "Analysis cancelled. Nothing was saved." in html_of(at)
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    assert _ws(at).list(RecordKind.PCAP_ANALYSES) == []


def test_hostile_capture_text_is_inert(fresh_runner, monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    result = {
        "filename": HOSTILE, "capture_format": "pcap", "ai_analysis": HOSTILE + "\n![x](http://127.0.0.1:9/a)",
        "ai_error": None, "protocol_hierarchy": [f"eth{HOSTILE} frames:1 bytes:2"],
        "conversations": [f"{HOSTILE} <-> 10.0.0.1  odd columns here"],
        "dns_queries": [{"dns.qry.name": HOSTILE}], "tls_sni": [], "http_requests": [],
        "general": {"top_dns_names": [[HOSTILE, 3]], "http_scanner_ua_hits": [{"user_agent": HOSTILE}]},
        "sip": {"messages": [{"sip.User-Agent": HOSTILE}],
                "aggregations": {"total_messages": 1, "scanner_ua_hits": [{"user_agent": HOSTILE}],
                                 "methods": [["INVITE", 1]]}},
        "rtp_streams_raw": ["a", "b", "c", HOSTILE], "truncated": ["dns"],
        "stored_rows": {"sip_messages": 2000},
    }
    ws = Workspace()
    record = ws.add(RecordKind.PCAP_ANALYSES, HOSTILE, {"filename": HOSTILE, "filesize_bytes": 2048,
                                                         "result": result})
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = record.id
    at.run()
    assert not at.exception
    body = html_of(at)
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;" in body
    for md in at.markdown:
        assert not md.allow_html
    assert "cut at the row limit for: dns" in body and "sip_messages (2000)" in body


def test_delete_and_unknown_id(fresh_runner, monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    ws = Workspace()
    record = ws.add(RecordKind.PCAP_ANALYSES, "a.pcap", {"filename": "a.pcap", "filesize_bytes": 10,
                                                         "result": {}})
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = "nope"
    at.run()
    assert "That analysis is not in this session" in html_of(at)
    at.query_params["id"] = record.id
    at.run()
    at.button(key="pcap_reader_del_danger").click().run()
    at.button(key="pcap_del_confirm_danger").click().run()
    assert not at.exception
    assert _ws(at).list(RecordKind.PCAP_ANALYSES) == []


@pytest.mark.parametrize("cut_short", [True, False])
def test_a_capture_cut_short_says_so(fresh_runner, monkeypatch, cut_short) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    ws = Workspace()
    record = ws.add(RecordKind.PCAP_ANALYSES, "cut.pcap", {
        "filename": "cut.pcap", "filesize_bytes": 234,
        "result": {"filename": "cut.pcap", "cut_short": cut_short, "ai_analysis": "ok", "dns_queries": []},
    })
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = record.id
    at.run()
    assert not at.exception
    assert (pcap_service.CUT_SHORT_NOTE in html_of(at)) is cut_short


def test_record_without_result(fresh_runner, monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    ws = Workspace()
    record = ws.add(RecordKind.PCAP_ANALYSES, "a.pcap", {"filename": "a.pcap"})
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = record.id
    at.run()
    assert "This saved analysis has no result to show." in html_of(at)


def test_without_a_key_outside_mock_mode(fresh_runner, tshark, uploaded, monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_MOCK_LLM")
    at = make_app(page.PAGE).run()
    assert "Add an OpenAI API key to run this step." in html_of(at)
    assert at.button(key="pcap_run").disabled


def test_trim_and_parsers() -> None:
    big = {"dns_queries": [{"a": i} for i in range(450)], "sip": {"messages": list(range(2000)),
           "aggregations": {"total_messages": 2000}}, "protocol_hierarchy": ["x"] * 300, "tls_sni": []}
    out = pcap_data.trim_for_storage(big)
    assert len(out["dns_queries"]) == pcap_data.STORED_ROWS and len(out["sip"]["messages"]) == 200
    assert out["stored_rows"] == {"dns_queries": 450, "sip_messages": 2000, "protocol_hierarchy": 300}
    assert out["sip"]["aggregations"]["total_messages"] == 2000
    assert len(big["dns_queries"]) == 450  # the original is not changed
    assert pcap_data.size_words(800) == "800 B" and pcap_data.size_words(4300) == "4.2 KB"
    assert pcap_data.size_words(3 * 1024 * 1024) == "3.0 MB" and pcap_data.size_words(None) == "unknown size"
    phs = pcap_data.phs_rows(["eth  frames:84 bytes:61230", "  ip  frames:84 bytes:61230", "junk", 5])
    assert phs == [{"Level": 1, "Protocol": "eth", "Frames": 84, "Bytes": 61230},
                   {"Level": 2, "Protocol": "ip", "Frames": 84, "Bytes": 61230}]
    conv = pcap_data.conversation_rows(["10.0.0.15 <-> 192.0.2.80  30 41000  20 9000  50 50000  0.0 20.1",
                                        "a <-> b 41 kB", "header"])
    assert conv[0]["Frames"] == 50 and conv[0]["Bytes"] == 50000 and conv[1]["Details"] == "41 kB"
    assert pcap_data.field_rows([{"ip.src": "1.2.3.4", "x": None}, 3]) == [{"Source": "1.2.3.4", "x": ""}]
    assert pcap_data.pair_rows([["a", 2], ["b", "x"], 7], "Name") == [{"Name": "a", "Count": 2}]
    assert pcap_data.field_rows("no") == [] and pcap_data.pair_rows(None, "x") == []


@pytest.mark.parametrize("sentence", sorted(pcap_service.JOB_ERRORS))
def test_a_failed_analysis_shows_the_services_own_sentence(fresh_runner, tshark, uploaded, monkeypatch,
                                                           sentence) -> None:
    """A timeout reads differently from a damaged file: the service's fixed
    sentences reach the visitor; any other exception text does not."""
    def fails(*args, **kwargs):
        raise pcap_service.PcapError(sentence)

    monkeypatch.setattr(pcap_service, "analyze_pcap", fails)
    at = _analyze(make_app(page.PAGE), fresh_runner, uploaded)
    assert sentence.replace("'", "&#x27;") in html_of(at)


def test_other_failure_text_is_never_shown(fresh_runner, tshark, uploaded, monkeypatch) -> None:
    def fails(*args, **kwargs):
        raise pcap_service.PcapError("tshark: /srv/uploads/secret-name.pcap is odd")

    monkeypatch.setattr(pcap_service, "analyze_pcap", fails)
    at = _analyze(make_app(page.PAGE), fresh_runner, uploaded)
    body = html_of(at)
    assert "The analysis did not finish." in body and "secret-name" not in body
