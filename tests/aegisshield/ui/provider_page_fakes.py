"""Fake model lists for the page tests and the browser check.

``FAKE_MODELS`` is what each fake provider lists. The ids other than the
app's own defaults are made up for tests; no app code names them.
``FakeModelLists`` stands in for ``providers.list_models``.
"""

from __future__ import annotations

from aegisshield.config import DEFAULT_MODEL_NAME, PRESELECTED_CLAUDE_MODEL
from aegisshield.core.errors import LLMError
from aegisshield.llm import providers
from aegisshield.llm.base import ERROR_LIST_FAILED, ModelInfo

FAKE_MODELS: dict[str, tuple[ModelInfo, ...]] = {
    "openai": (ModelInfo(DEFAULT_MODEL_NAME), ModelInfo("test-chat-b")),
    "claude": (ModelInfo(PRESELECTED_CLAUDE_MODEL, True), ModelInfo("test-claude-text", False)),
    "bedrock": (ModelInfo("test.text-model-v1:0", False), ModelInfo("us.test.vision-model-v1:0", True)),
    "gemini": (ModelInfo("test-gemini-a"), ModelInfo("test-gemini-b")),
}


class FakeModelLists:
    """Stands in for ``providers.list_models``, so no page ever asks a real
    provider. It answers with ``models[provider]`` (cleaned as the real
    listing is), or fails with the fixed sentence for a provider in
    ``failing``, and records each call without the credential."""

    def __init__(self) -> None:
        self.models: dict[str, tuple[ModelInfo, ...]] = dict(FAKE_MODELS)
        self.failing: set[str] = set()
        self.calls: list[str] = []

    def __call__(self, provider: object, credential: object, **_kwargs: object) -> tuple[ModelInfo, ...]:
        name = providers.Provider(provider).value
        missing = providers.missing_credential(name, credential)
        if missing:
            raise LLMError(missing)
        self.calls.append(name)
        if name in self.failing:
            raise LLMError(ERROR_LIST_FAILED)
        return providers.clean_models(self.models.get(name, ()))
