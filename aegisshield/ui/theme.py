"""The app's look: design tokens, area accents, and the stylesheet.

Colors, fonts, radii, and padding are set natively in
``.streamlit/config.toml``. ``assets/theme.css`` adds only what the native
theme cannot express. :func:`apply_theme` injects it once per script run.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

import streamlit as st

__all__ = [
    "ASSETS_DIR",
    "BRAND_DIR",
    "TOKENS",
    "Area",
    "Tone",
    "apply_theme",
    "area_class",
    "contrast_ratio",
    "stylesheet",
]

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
# The logo set: "light" artwork (navy) is for light backgrounds, "dark"
# artwork (white) for dark ones.
BRAND_DIR = ASSETS_DIR / "brand"
_CSS_PATH = ASSETS_DIR / "theme.css"


class Area(StrEnum):
    """The part of the product a page belongs to; it sets the accent color."""

    DEFENSE = "defense"
    COMPLIANCE = "compliance"
    NEUTRAL = "neutral"


class Tone(StrEnum):
    """Semantic color of a badge, tile, or notice. Always paired with words."""

    NEUTRAL = "neutral"
    ACCENT = "accent"
    INFO = "info"
    OK = "ok"
    WARN = "warn"
    CRIT = "crit"


# The design tokens as opaque hex values, so contrast can be checked in
# tests. Translucent tokens are given as the color they produce over
# --bg-base.
TOKENS: dict[str, str] = {
    "bg-base": "#080c14",
    "bg-surface": "#131a2b",
    "bg-raised": "#10162a",
    "bg-sidebar": "#0c1018",
    "bg-terminal": "#060a10",
    "border": "#192131",
    "border-strong": "#222d42",
    "text-primary": "#e2e8f0",
    "text-soft": "#94a3b8",
    "text-muted": "#7b8aa3",
    "area-blue": "#3b82f6",
    "area-grc": "#22b8cf",
    "accent-text": "#60a5fa",
    "grc-text": "#5fd3e6",
    "button-primary": "#2563eb",
    "button-danger": "#b91c1c",
    "ok-text": "#4ade80",
    "warn-text": "#fbbf24",
    "crit-text": "#f87171",
    "info-text": "#7dd3fc",
}


def area_class(area: Area | str) -> str:
    """The CSS class for ``area``; raises ``ValueError`` for an unknown area.

    Only enum values reach the page, so no free text is placed in markup.
    """
    return f"ax-area-{Area(area).value}"


@lru_cache(maxsize=1)
def stylesheet() -> str:
    """The app stylesheet. Public, read once per process."""
    return _CSS_PATH.read_text(encoding="utf-8")


def apply_theme() -> None:
    """Inject the stylesheet. Call once per script run, before any page body.

    ``st.html`` sends a style-only body to the event container, so this adds
    no gap to the layout.
    """
    st.html(f"<style>{stylesheet()}</style>")


def _channel(value: int) -> float:
    c = value / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2 contrast ratio between two ``#rrggbb`` colors."""
    a, b = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (a + 0.05) / (b + 0.05)
