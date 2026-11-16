"""Fixtures for the scan tests: a fake garak interpreter and a clean cache."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisshield.aiscan import availability
from tests.aegisshield.aiscan.garak_fakes import FakeGarak, install


@pytest.fixture
def fake_garak(tmp_path: Path) -> FakeGarak:
    """A fake garak interpreter (see ``fake_garak.py``)."""
    return install(tmp_path / "garak-env")


@pytest.fixture(autouse=True)
def _clean_version_cache():
    availability.clear_cache()
    yield
    availability.clear_cache()


@pytest.fixture
def private_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[], list[str]]:
    """Point ``tempfile`` at a fresh directory; returns a lister of what is left there."""
    import tempfile

    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return lambda: sorted(os.listdir(root))
