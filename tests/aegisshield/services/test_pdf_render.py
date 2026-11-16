"""Every PDF the app makes is drawn under the locked resource policy: an
image or stylesheet reference fetches nothing over the network and reads no
local file. Each local case has a positive control that shows the same
markup does load the resource under an open policy, so a pass is not an
accident of the markup."""

from __future__ import annotations

import io
import shutil
import socket
from pathlib import Path

import pytest
from pypdf import PdfReader
from xhtml2pdf import pisa

from aegisshield.services import pdf_render, policy_service, report_service

LOGO = Path(__file__).resolve().parents[3] / "aegisshield" / "ui" / "assets" / "brand" / "logo-light.png"
RED = b"1 0 0 rg"


def _images(pdf: bytes) -> int:
    return sum(len(page.images) for page in PdfReader(io.BytesIO(pdf)).pages)


def _content(pdf: bytes) -> bytes:
    return b"".join(page.get_contents().get_data() for page in PdfReader(io.BytesIO(pdf)).pages)


def _open_render(html_doc: str) -> bytes:
    out = io.BytesIO()
    pisa.CreatePDF(html_doc, dest=out)  # xhtml2pdf's default policy
    return out.getvalue()


@pytest.fixture
def local_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """An image and a stylesheet inside the working directory, which is
    where xhtml2pdf's own default policy lets a document read from."""
    monkeypatch.chdir(tmp_path)
    image = tmp_path / "logo.png"
    shutil.copyfile(LOGO, image)
    sheet = tmp_path / "red.css"
    sheet.write_text("p { color: #ff0000; }")
    return {"image": str(image), "image_uri": image.as_uri(), "sheet": str(sheet),
            "sheet_uri": sheet.as_uri()}


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record and refuse every outgoing connection."""
    attempts: list[object] = []

    def refuse(self, address, *args, **kwargs):  # noqa: ANN001, ANN202
        attempts.append(address)
        raise OSError("network refused in tests")

    def refuse_create(address, *args, **kwargs):  # noqa: ANN001, ANN202
        attempts.append(address)
        raise OSError("network refused in tests")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse_create)
    monkeypatch.setattr(socket, "getaddrinfo", refuse_create)
    return attempts


def _documents(files: dict[str, str]) -> dict[str, str]:
    def page(head: str = "", body: str = "") -> str:
        return f"<html><head>{head}</head><body><p>text</p>{body}</body></html>"

    return {
        "file image": page(body=f'<img src="{files["image_uri"]}" />'),
        "absolute path image": page(body=f'<img src="{files["image"]}" />'),
        "file stylesheet import": page(head=f'<style>@import url("{files["sheet_uri"]}");</style>'),
        "absolute path stylesheet import": page(head=f'<style>@import "{files["sheet"]}";</style>'),
        "linked stylesheet": page(head=f'<link rel="stylesheet" href="{files["sheet"]}" />'),
    }


def _loaded(name: str, pdf: bytes) -> bool:
    return _images(pdf) > 0 if "image" in name else RED in _content(pdf)


def test_the_local_cases_do_load_under_the_default_policy(local_files) -> None:
    for name, doc in _documents(local_files).items():
        assert _loaded(name, _open_render(doc)), name


@pytest.mark.parametrize("render", [
    pdf_render.html_to_pdf,
    report_service.render_pdf,
    "policy",
])
def test_no_local_file_is_read(render, local_files, monkeypatch) -> None:
    for name, doc in _documents(local_files).items():
        if render == "policy":
            monkeypatch.setattr(policy_service, "build_policy_html", lambda _p, doc=doc: doc)
            pdf = policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})
        else:
            pdf = render(doc)
        assert pdf.startswith(b"%PDF"), name
        assert not _loaded(name, pdf), name


REMOTE = (
    '<html><head><style>@import url("http://127.0.0.1:9/a.css");</style>'
    '<link rel="stylesheet" href="https://tracker.example/b.css" /></head>'
    '<body><p>x</p><img src="http://127.0.0.1:9/a.png" />'
    '<img src="https://tracker.example/p.png" /></body></html>'
)


def test_no_network_fetch_from_the_shared_renderer(no_network) -> None:
    pdf = pdf_render.html_to_pdf(REMOTE)
    assert pdf.startswith(b"%PDF") and _images(pdf) == 0
    assert no_network == []


def test_no_network_fetch_from_the_policy_pdf(no_network, monkeypatch) -> None:
    monkeypatch.setattr(policy_service, "build_policy_html", lambda _p: REMOTE)
    pdf = policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})
    assert pdf.startswith(b"%PDF") and no_network == []


def test_policy_text_with_hostile_references_fetches_nothing(no_network) -> None:
    body = ("![a](http://127.0.0.1:9/a.png)\n\n![b](file:///etc/hosts)\n\n"
            '<style>@import url("http://127.0.0.1:9/x.css");</style>\n\n'
            '<img src="file:///etc/hosts">')
    pdf = policy_service.render_policy_pdf({"title": "T", "body_markdown": body})
    assert pdf.startswith(b"%PDF") and _images(pdf) == 1  # the embedded logo only
    assert no_network == []


def test_a_data_uri_still_loads() -> None:
    import base64

    logo = base64.b64encode(LOGO.read_bytes()).decode()
    pdf = pdf_render.html_to_pdf(f'<html><body><img src="data:image/png;base64,{logo}" /></body></html>')
    assert _images(pdf) == 1


def test_the_logo_keeps_its_transparency_on_the_page() -> None:
    """The logo is drawn with a soft mask, so its transparent margin stays
    white paper instead of printing as a black box."""
    pdf = policy_service.render_policy_pdf({"title": "T", "body_markdown": "Body."})
    reader = PdfReader(io.BytesIO(pdf))
    images = [obj.get_object() for page in reader.pages
              for obj in page["/Resources"]["/XObject"].values()]
    found = [x for x in images if x.get("/Subtype") == "/Image"]
    found += [inner.get_object() for x in images if x.get("/Subtype") == "/Form"
              for inner in x["/Resources"]["/XObject"].values()
              if inner.get_object().get("/Subtype") == "/Image"]
    assert found and all("/SMask" in x for x in found)


def test_render_failures_become_a_fixed_error(monkeypatch) -> None:
    class Status:
        err = 1

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", lambda *a, **k: Status())
    with pytest.raises(pdf_render.PdfRenderError, match="could not be generated"):
        pdf_render.html_to_pdf("<p>x</p>")
    with pytest.raises(policy_service.PolicyRenderError):
        policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})

    def boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise ValueError("parser broke")

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", boom)
    with pytest.raises(pdf_render.PdfRenderError):
        pdf_render.html_to_pdf("<p>x</p>")


def test_the_policy_is_xhtml2pdfs_server_policy_with_remote_off() -> None:
    from xhtml2pdf.config.resources import ResourceAccessPolicy

    policy = pdf_render.locked_resource_policy()
    server = ResourceAccessPolicy.server(None)
    assert (policy.allow_remote, policy.base_dir, policy.allow_remote_pdf_backgrounds) == (False, None, False)
    assert policy.max_document_bytes == pdf_render.MAX_DOCUMENT_BYTES
    assert policy.max_render_seconds == pdf_render.MAX_RENDER_SECONDS
    # Every other server limit is kept as xhtml2pdf sets it.
    for name in ("max_depth", "max_resources", "max_total_bytes", "max_image_pixels", "max_local_bytes"):
        assert getattr(policy, name) == getattr(server, name) is not None


def test_an_oversized_document_is_a_fixed_error(monkeypatch) -> None:
    monkeypatch.setattr(pdf_render, "MAX_DOCUMENT_BYTES", 2_000)
    with pytest.raises(pdf_render.PdfRenderError):
        pdf_render.html_to_pdf("<html><body>" + "<p>text</p>" * 400 + "</body></html>")


def test_a_render_over_its_time_is_a_fixed_error(monkeypatch) -> None:
    monkeypatch.setattr(pdf_render, "MAX_RENDER_SECONDS", 1e-9)
    with pytest.raises(pdf_render.PdfRenderError):
        pdf_render.html_to_pdf("<html><body>" + "<p>text</p>" * 400 + "</body></html>")


def test_deep_nesting_is_a_fixed_error_not_a_crash() -> None:
    with pytest.raises(pdf_render.PdfRenderError):
        pdf_render.html_to_pdf("<html><body>" + "<div>" * 400 + "x" + "</div>" * 400 + "</body></html>")


def test_headings_never_read_the_system_random_source(monkeypatch) -> None:
    """Each heading's outline key comes from a counter, not ``uuid4``; the
    syscall behind ``uuid4`` stalled other threads (see pdf_render)."""
    import os

    def no_urandom(_n: int) -> bytes:
        raise AssertionError("os.urandom called during a render")

    assert pdf_render.OUTLINE_KEYS_PATCHED, "xhtml2pdf moved the module or name the counter replaces"
    monkeypatch.setattr(os, "urandom", no_urandom)
    pdf = pdf_render.html_to_pdf("<html><body>" + "<h2>Heading</h2><p>text</p>" * 5 + "</body></html>")
    assert pdf.startswith(b"%PDF")


def test_a_long_policy_pdf_does_not_stall_other_threads() -> None:
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    para = "The service must log every access to customer records and review logs weekly. " * 4
    section = f"## Section\n\n{para}\n\n- item {para[:60]}\n- item two\n\n"
    body = (section * (policy_service.MAX_BODY_CHARS // len(section)))[: policy_service.MAX_BODY_CHARS]
    run = least_stall(policy_service.render_policy_pdf, {"title": "Policy", "body_markdown": body}, repeats=2)
    assert run.result.startswith(b"%PDF")
    assert run.stall < STALL_LIMIT_S * 0.6, run


def test_a_report_with_long_sections_does_not_stall_other_threads() -> None:
    """Every markdown section of the threat model report at a quarter of the
    render cap."""
    from aegisshield.services.markdown_render import MAX_RENDER_CHARS
    from tests.aegisshield.stall import STALL_LIMIT_S, measure

    para = "The service must log every access to customer records and review logs weekly. " * 4
    section = f"## Section\n\n{para}\n\n- item {para[:60]}\n- item two\n\n| a | b |\n|---|---|\n| x | y |\n\n"
    text = (section * (MAX_RENDER_CHARS // 4 // len(section) + 1))[: MAX_RENDER_CHARS // 4]
    fields = ("mitigations_markdown", "dread_assessment_markdown", "test_cases_markdown",
              "mitre_attack_markdown", "nvd_vulnerabilities_markdown", "otx_data_markdown")
    run = measure(report_service.generate_pdf_bytes, dict.fromkeys(fields, text), {}, text)
    assert run.result.startswith(b"%PDF")
    assert run.stall < STALL_LIMIT_S * 0.8, run


def test_a_report_over_the_document_limit_is_the_fixed_error() -> None:
    from aegisshield.core.errors import AegisError

    threats = [{"Threat Type": "Spoofing", "Scenario": "x" * 1000} for _ in range(2000)]
    with pytest.raises(AegisError):
        report_service.generate_pdf_bytes({"threat_model": threats}, {}, "description")


# ------------------------------------------------- CPU bounds and logging


def _table(rows: int) -> str:
    return "<html><body><table>" + "<tr><td>a</td><td>b</td></tr>" * rows + "</table></body></html>"


def test_the_render_time_limit_is_a_few_seconds() -> None:
    assert 0 < pdf_render.MAX_RENDER_SECONDS <= 10
    assert pdf_render.locked_resource_policy().max_render_seconds == pdf_render.MAX_RENDER_SECONDS


def test_a_table_over_the_row_limit_is_refused_before_rendering(monkeypatch) -> None:
    def never(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("xhtml2pdf was called")

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", never)
    with pytest.raises(pdf_render.PdfRenderError, match="table is too long") as caught:
        pdf_render.html_to_pdf(_table(pdf_render.MAX_TABLE_ROWS + 1))
    assert "HTML report" in str(caught.value)


def test_a_table_at_the_row_limit_renders() -> None:
    assert pdf_render.html_to_pdf(_table(pdf_render.MAX_TABLE_ROWS)).startswith(b"%PDF")


def test_rows_are_counted_per_table() -> None:
    many_small = "<html><body>" + ("<table>" + "<tr><td>a</td></tr>" * 3 + "</table>") * 400 + "</body></html>"
    assert pdf_render.longest_table_rows(many_small) == 3
    assert pdf_render.longest_table_rows(_table(7)) == 7
    assert pdf_render.longest_table_rows("<TABLE><TR><td>x</td></TR><Tr></Tr></table>") == 2
    assert pdf_render.longest_table_rows("<p>no table</p><tr>") == 0
    # an unclosed table still counts its rows
    assert pdf_render.longest_table_rows("<table><tr><tr><tr>") == 3


def test_row_counting_neither_stalls_nor_grows_faster_than_the_document() -> None:
    import time

    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    def timed(doc: str) -> float:
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            pdf_render.longest_table_rows(doc)
            best = min(best, time.perf_counter() - start)
        return best

    for unit in ("<table><tr>", "<tr", "<" , "</table><table", "<table " + "x" * 50):
        large = unit * (pdf_render.MAX_DOCUMENT_BYTES // len(unit))
        small = large[: len(large) // 4]
        # Four times the input; a quadratic scan would take sixteen times.
        assert timed(large) < 8 * timed(small) + 0.05, unit
        assert least_stall(pdf_render.longest_table_rows, large, repeats=2).stall < STALL_LIMIT_S, unit


def test_the_report_with_a_long_tiny_cell_table_is_refused_quickly() -> None:
    """A 100,000-character table of tiny cells took about 30 s of CPU to draw."""
    import time

    from aegisshield.core.errors import AegisError

    table = "| a | b | c | d |\n|---|---|---|---|\n" + "| a | b | c | d |\n" * (100_000 // 18)
    started = time.monotonic()
    with pytest.raises(AegisError, match="table is too long"):
        report_service.generate_pdf_bytes({"mitigations_markdown": table}, {}, "description")
    assert time.monotonic() - started < 2


def test_renders_past_the_concurrency_limit_are_refused(monkeypatch) -> None:
    import threading

    gate = threading.Event()
    entered = threading.Semaphore(0)
    real = pdf_render.pisa.CreatePDF

    def slow(*a, **k):  # noqa: ANN002, ANN003, ANN202
        entered.release()
        gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", slow)
    results: list[object] = []
    workers = [threading.Thread(target=lambda: results.append(pdf_render.html_to_pdf("<p>x</p>")))
               for _ in range(pdf_render.MAX_CONCURRENT_RENDERS)]
    for w in workers:
        w.start()
    for _ in workers:
        assert entered.acquire(timeout=10)
    try:
        with pytest.raises(pdf_render.PdfBusyError, match="busy"):
            pdf_render.html_to_pdf("<p>x</p>")
    finally:
        gate.set()
        for w in workers:
            w.join(10)
    assert len(results) == pdf_render.MAX_CONCURRENT_RENDERS
    assert all(isinstance(r, bytes) for r in results)
    # the slots are free again
    assert pdf_render.html_to_pdf("<p>x</p>").startswith(b"%PDF")


def test_a_refused_render_reaches_the_callers_as_their_plain_errors(monkeypatch) -> None:
    from aegisshield.core.errors import AegisError

    def busy(_html: str) -> bytes:
        raise pdf_render.PdfBusyError(pdf_render.BUSY_MESSAGE)

    monkeypatch.setattr(report_service, "html_to_pdf", busy)
    monkeypatch.setattr(policy_service, "html_to_pdf", busy)
    with pytest.raises(AegisError, match="busy"):
        report_service.render_pdf("<p>x</p>")
    with pytest.raises(policy_service.PolicyRenderError, match="busy"):
        policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})


def test_a_parser_exception_is_logged_by_class_only(monkeypatch, caplog) -> None:
    def boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise ValueError("quoted document text: shopper card 4111")

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", boom)
    with caplog.at_level("DEBUG", logger="aegisshield.services.pdf_render"), \
            pytest.raises(pdf_render.PdfRenderError):
        pdf_render.html_to_pdf("<p>x</p>")
    assert "ValueError" in caplog.text
    assert "quoted document text" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
