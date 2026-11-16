"""Shared fixtures for the UI tests: a clean environment and no operator secrets."""

from __future__ import annotations

import pytest

from aegisshield.llm import providers
from aegisshield.ui import state
from tests.aegisshield.ui.provider_page_fakes import FAKE_MODELS, FakeModelLists

__all__ = ["FAKE_MODELS", "FakeModelLists"]

# The real reader, kept before the autouse fixture replaces it.
REAL_SECRET = state._secret

_ENV = ("AEGIS_MOCK_LLM", "AEGIS_DATA_DIR", "AEGIS_AGENTIC", "AEGIS_OFFLINE",
        "AEGIS_ARCHITECT_MODEL", "AEGIS_WORKER_MODEL", "AEGIS_PROVIDERS")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """No AEGIS_* settings and no secrets.toml lookups (never the real one)."""
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(state, "_secret", lambda name: "")


@pytest.fixture
def mock_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")


@pytest.fixture(autouse=True)
def model_lists(monkeypatch: pytest.MonkeyPatch) -> FakeModelLists:
    """Every UI test gets fake model lists (see ``FakeModelLists``)."""
    fake = FakeModelLists()
    monkeypatch.setattr(providers, "list_models", fake)
    return fake
