"""HTML to PDF for every PDF the app makes, with nothing fetched or read.

Model output and visitor text end up in these documents. They are escaped
before they get here, but the renderer itself is also locked. Its resource
policy is xhtml2pdf's own policy for HTML you did not write
(``ResourceAccessPolicy.server``) with remote fetches off: no network fetch
and no local file read (no base directory names none, which denies local
reads), for images, stylesheets, and CSS ``@import`` alike, plus limits on
document size, element nesting, and render time. Only ``data:`` URIs
embedded in the document load, which is how the logo gets in.

Drawing a PDF is CPU work in the shared process, so it is also bounded
before it starts: a table longer than ``MAX_TABLE_ROWS`` is refused (the
time to draw one table grows faster than its length), and at most
``MAX_CONCURRENT_RENDERS`` renders run at once in the process; another is
refused at once rather than queued.
"""

from __future__ import annotations

import io
import itertools
import logging
import re
import threading
import uuid

from xhtml2pdf import pisa
from xhtml2pdf.config.resources import ResourceAccessPolicy

from aegisshield.core.errors import AegisError

logger = logging.getLogger(__name__)

# The largest HTML document a render accepts, and how long a render may run
# (xhtml2pdf checks the clock between elements, so this is a bound, not a
# precise stop). Every document is built from text already clipped to
# ``markdown_render.MAX_RENDER_CHARS`` per section; a threat model report
# with every section at that cap is about 1.05 MB of HTML and 6,400 table
# cells in short tables, and draws in about 3.2 s of CPU on an Apple M-series
# machine; the time limit leaves room for a slower host.
# The size limit also bounds the stall from the garbage collector, whose
# full passes over the PDF's objects hold the interpreter lock: about
# 0.04 s at 1 MB of HTML, 0.07 s at 2 MB, 0.14 s at 4 MB. Anything larger,
# such as an imported record with thousands of threats, is refused with
# the fixed error.
MAX_DOCUMENT_BYTES = 1536 * 1024
MAX_RENDER_SECONDS = 8

# One table's drawing time grows faster than its row count inside the report
# stylesheet: 500 rows of four short cells take about 0.5 s, 2,000 rows 3.8 s,
# and 4,000 rows 15 s. A table longer than this is refused before drawing.
# The longest table a generated threat model writes has one row per threat.
MAX_TABLE_ROWS = 500

# Renders running at once in the whole process. A render holds the
# interpreter for most of its time, so more at once would only slow every
# visitor's page.
MAX_CONCURRENT_RENDERS = 2
_render_slots = threading.BoundedSemaphore(MAX_CONCURRENT_RENDERS)

RENDER_FAILED_MESSAGE = "The PDF could not be generated."
BUSY_MESSAGE = "The server is busy drawing other PDFs. Try again in a minute, or download the HTML report."
TABLE_MESSAGE = (f"A table is too long for a PDF (more than {MAX_TABLE_ROWS} rows). "
                 "Download the HTML report instead.")
_TABLE_TAG = re.compile(r"<(/?)(table|tr)\b", re.IGNORECASE)

# xhtml2pdf names each heading's PDF outline entry with ``uuid4()``, which
# reads the operating system's random source on every heading. That call
# gives up the interpreter lock and takes it straight back, and a stream of
# them, one every few milliseconds, kept a second thread from running for
# 0.25 to 0.35 s at a time on a 200,000-character policy (0.04 s without
# them). The key only has to be unique within one document, so a counter
# stands in; nothing here is secret or visitor-specific.
_toc_keys = itertools.count(1)


def _toc_key() -> uuid.UUID:
    return uuid.UUID(int=next(_toc_keys))


def _use_counter_for_outline_keys() -> bool:
    """Point xhtml2pdf's outline naming at the counter; False if it moved.

    This reaches into a module xhtml2pdf does not document. If a later
    release renames it or stops using ``uuid4`` there, PDFs still render
    (only this speed-up is lost), and a test fails to say so.
    """
    try:
        from xhtml2pdf import xhtml2pdf_reportlab
    except ImportError:
        return False
    if not hasattr(xhtml2pdf_reportlab, "uuid4"):
        return False
    xhtml2pdf_reportlab.uuid4 = _toc_key  # type: ignore[attr-defined]
    return True


OUTLINE_KEYS_PATCHED = _use_counter_for_outline_keys()


class PdfRenderError(AegisError):
    """The document was not drawn. The message is a fixed sentence a visitor
    can read."""


class PdfBusyError(PdfRenderError):
    """Every render slot was taken, so this render did not start."""


def pdf_message(exc: PdfRenderError, fallback: str) -> str:
    """The sentence to show for ``exc``: its own when it names a reason the
    visitor can act on (busy, a table too long), otherwise ``fallback``."""
    reason = str(exc)
    return reason if reason in (BUSY_MESSAGE, TABLE_MESSAGE) else fallback


def longest_table_rows(html_content: str) -> int:
    """The most ``<tr>`` rows inside any one ``<table>`` (one linear scan).

    Rows of a table that is never closed count toward it; rows outside every
    table count toward none.
    """
    longest = 0
    counts: list[int] = []
    for match in _TABLE_TAG.finditer(html_content):
        closing, tag = match.group(1), match.group(2).lower()
        if tag == "table":
            if closing:
                if counts:
                    counts.pop()
            else:
                counts.append(0)
        elif not closing and counts:
            counts[-1] += 1
            longest = max(longest, counts[-1])
    return longest


def locked_resource_policy() -> ResourceAccessPolicy:
    """The resource policy every PDF render uses: no network, no local files,
    and xhtml2pdf's server limits with the document size and render time
    set for this app."""
    return ResourceAccessPolicy.server(
        None,
        allow_remote=False,
        max_document_bytes=MAX_DOCUMENT_BYTES,
        max_render_seconds=MAX_RENDER_SECONDS,
    )


def html_to_pdf(html_content: str) -> bytes:
    """Draw ``html_content`` as PDF bytes under ``locked_resource_policy``.

    Raises ``PdfRenderError`` with a fixed sentence when a table is too long,
    xhtml2pdf fails, or a limit is reached, and ``PdfBusyError`` when every
    render slot is taken. Only the exception's class is logged: a parser's
    message or traceback can quote the document.
    """
    if longest_table_rows(html_content) > MAX_TABLE_ROWS:
        logger.warning("PDF refused: a table has more than %d rows", MAX_TABLE_ROWS)
        raise PdfRenderError(TABLE_MESSAGE)
    if not _render_slots.acquire(blocking=False):
        logger.warning("PDF refused: %d renders already running", MAX_CONCURRENT_RENDERS)
        raise PdfBusyError(BUSY_MESSAGE)
    try:
        return _render(html_content)
    finally:
        _render_slots.release()


def _render(html_content: str) -> bytes:
    output = io.BytesIO()
    try:
        status = pisa.CreatePDF(html_content, dest=output, resource_policy=locked_resource_policy())
    # xhtml2pdf raises a wide range of exception types from its parsers and
    # reportlab (RecursionError and its own RenderLimitError among them); any
    # of them means the same thing to the caller.
    except Exception as exc:
        logger.error("xhtml2pdf raised %s while rendering a PDF", type(exc).__name__)
        raise PdfRenderError(RENDER_FAILED_MESSAGE) from exc
    if status.err:
        logger.error("xhtml2pdf reported %s error(s) while rendering a PDF", status.err)
        raise PdfRenderError(RENDER_FAILED_MESSAGE)
    return output.getvalue()
