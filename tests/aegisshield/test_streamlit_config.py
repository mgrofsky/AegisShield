"""The server's upload cap in .streamlit/config.toml stays in step with the
largest upload a page takes."""

from __future__ import annotations

import tomllib
from pathlib import Path

from aegisshield.services import pcap_service
from aegisshield.storage.workspace import MAX_WORKSPACE_BYTES
from aegisshield.ui import options

CONFIG = Path(__file__).resolve().parents[2] / ".streamlit" / "config.toml"
MB = 1024 * 1024


def test_server_upload_cap_covers_every_page_and_no_more() -> None:
    server = tomllib.loads(CONFIG.read_text(encoding="utf-8"))["server"]
    cap_bytes = server["maxUploadSize"] * MB
    largest = max(pcap_service.MAX_UPLOAD_BYTES, MAX_WORKSPACE_BYTES, options.MAX_IMAGE_BYTES)
    # Large enough for every page's own limit, and no larger than the largest.
    assert cap_bytes == largest
