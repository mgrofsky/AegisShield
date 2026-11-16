"""Theme tokens meet WCAG AA, and the stylesheet keeps to stable selectors."""

from __future__ import annotations

import re

import pytest

from aegisshield.ui import theme
from aegisshield.ui.theme import TOKENS, contrast_ratio

T = TOKENS
SURFACES = ["bg-base", "bg-surface", "bg-raised", "bg-sidebar", "bg-terminal"]
BODY_TEXT = ["text-primary", "text-soft", "text-muted", "accent-text", "grc-text",
             "ok-text", "warn-text", "crit-text", "info-text"]


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("text", BODY_TEXT)
def test_text_tokens_meet_aa_on_every_surface(text: str, surface: str) -> None:
    assert contrast_ratio(T[text], T[surface]) >= 4.5


@pytest.mark.parametrize("button", ["button-primary", "button-danger"])
def test_white_button_text_meets_aa(button: str) -> None:
    assert contrast_ratio("#ffffff", T[button]) >= 4.5


@pytest.mark.parametrize("accent", ["area-blue", "area-grc"])
def test_accent_marks_meet_non_text_contrast(accent: str) -> None:
    assert contrast_ratio(T[accent], T["bg-base"]) >= 3.0


def test_contrast_ratio_known_values() -> None:
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0)


def test_area_class_only_accepts_known_areas() -> None:
    assert theme.area_class("compliance") == "ax-area-compliance"
    with pytest.raises(ValueError):
        theme.area_class("offense")


def test_stylesheet_uses_no_generated_class_names() -> None:
    css = theme.stylesheet()
    assert "st-emotion-cache" not in css
    assert not re.search(r"\.e1[a-z0-9]{5,}", css)


def test_stylesheet_respects_reduced_motion_and_has_no_red_area() -> None:
    css = theme.stylesheet()
    assert "prefers-reduced-motion: reduce" in css
    assert "area-red" not in css and "offense" not in css.lower()


def test_apply_theme_injects_one_style_block(monkeypatch: pytest.MonkeyPatch) -> None:
    import streamlit as st

    out: list[str] = []
    monkeypatch.setattr(st, "html", lambda body, **_: out.append(body))
    theme.apply_theme()
    assert len(out) == 1 and out[0].startswith("<style>") and out[0].endswith("</style>")
