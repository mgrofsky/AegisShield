"""The logo set: every file is a small, clean PNG, and the readme and the app
point at files that exist."""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from aegisshield.services import policy_service, report_service
from aegisshield.ui import app
from aegisshield.ui.theme import BRAND_DIR

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ("logo-light.png", "logo-dark.png", "icon-light.png", "icon-dark.png", "favicon.png")
# Critical chunks plus transparency: no text, time, EXIF, XMP, or other metadata.
ALLOWED_CHUNKS = {"IHDR", "PLTE", "tRNS", "IDAT", "IEND"}
MAX_BYTES = 80 * 1024


def _chunks(data: bytes) -> list[str]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    names, rest = [], data[8:]
    while rest:
        (length,) = struct.unpack(">I", rest[:4])
        names.append(rest[4:8].decode("latin-1"))
        rest = rest[12 + length:]
    return names


@pytest.mark.parametrize("name", ASSETS)
def test_brand_asset_is_a_small_png_with_no_metadata(name: str) -> None:
    path = BRAND_DIR / name
    data = path.read_bytes()
    chunks = _chunks(data)
    assert chunks[0] == "IHDR" and chunks[-1] == "IEND"
    assert set(chunks) <= ALLOWED_CHUNKS, chunks
    assert len(data) < MAX_BYTES


def test_brand_dir_holds_only_the_known_assets() -> None:
    assert sorted(p.name for p in BRAND_DIR.iterdir()) == sorted(ASSETS)


def test_readme_picture_block_points_at_files_that_exist() -> None:
    readme = (ROOT / "readme.md").read_text(encoding="utf-8")
    block = re.search(r"<picture>(.*?)</picture>", readme, re.S)
    assert block, "the readme has no picture block"
    targets = re.findall(r'(?:srcset|src)="([^"]+)"', block.group(1))
    assert len(targets) == 3
    assert {Path(t).name for t in targets} == {"logo-dark.png", "logo-light.png"}
    for target in targets:
        assert (ROOT / target).is_file(), target


def test_documents_use_the_light_background_logo() -> None:
    assert report_service.LOGO_PATH == BRAND_DIR / "logo-light.png"
    assert policy_service._LOGO_PATH == BRAND_DIR / "logo-light.png"


def test_the_page_is_dark_only_so_the_sidebar_uses_white_artwork() -> None:
    config = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    css = (BRAND_DIR.parent / "theme.css").read_text(encoding="utf-8")
    assert re.search(r'^base = "dark"$', config, re.M)
    assert "prefers-color-scheme" not in css
    assert app.SIDEBAR_ICON == BRAND_DIR / "icon-dark.png"


def test_document_logo_keeps_its_transparency_in_a_pdf() -> None:
    """xhtml2pdf drops a palette PNG's transparency, which prints the logo on a
    black box; the document logo must be stored with an alpha channel."""
    data = (BRAND_DIR / "logo-light.png").read_bytes()
    color_type = data[25]  # IHDR: width, height, bit depth, then color type
    assert color_type == 6  # RGBA
