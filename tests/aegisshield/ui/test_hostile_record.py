"""A visitor imports a workspace whose record holds hostile text in every
rendered field, then opens the record. The import is accepted (it is within every limit), the page renders, and a
second thread is never stalled for long while it does."""

from __future__ import annotations

import json

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.storage import RecordKind, Workspace
from aegisshield.storage.workspace import MAX_STRING_CHARS
from tests.aegisshield.stall import STALL_LIMIT_S, measure
from tests.aegisshield.ui.tm_records import mock_payload

N = MAX_STRING_CHARS


def _rep(unit: str) -> str:
    return (unit * (N // len(unit) + 1))[:N]


def _app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_model_detail
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    threat_model_detail.render()


HOSTILE = {
    "the kit pattern's input": "[](" + " " * (N - 4) + "x",
    "backticks and pipes": _rep("`|"),
    "unclosed links": _rep("[a](a"),
    "fence lines": _rep("```gherkin\n\n"),
}


def test_a_record_dense_with_brackets_is_refused_before_parsing() -> None:
    """``[a](`` in every field holds more brackets than the import allows
    (``MAX_CONTAINERS``), so it is refused before ``json.loads`` runs."""
    from aegisshield.core.errors import WorkspaceError

    payload = {key: _rep("[a](") for key in mock_payload() if key.endswith("_markdown")}
    source = Workspace()
    source.add(RecordKind.THREAT_MODELS, "Imported", payload)
    with pytest.raises(WorkspaceError):
        Workspace.from_json(json.dumps(source.to_dict()).encode())


@pytest.mark.parametrize("name", list(HOSTILE))
def test_an_imported_hostile_record_opens_without_stalling_other_visitors(name: str) -> None:
    text = HOSTILE[name]
    payload = mock_payload()
    fields = [k for k in payload if k.endswith("_markdown")] + ["attack_tree_code", "description"]
    if text.count("[") > 20_000:
        # One field only: more would pass the import's bracket limit.
        fields = ["test_cases_markdown"]
    for key in fields:
        payload[key] = text
    source = Workspace()
    source.add(RecordKind.THREAT_MODELS, "Imported", payload)
    data = json.dumps(source.to_dict()).encode()

    workspace = Workspace.from_json(data)  # within every import limit
    (record,) = workspace.list(RecordKind.THREAT_MODELS)
    at = AppTest.from_function(_app, default_timeout=60)
    at.session_state["aegis_workspace"] = workspace
    at.query_params["id"] = record.id

    run = measure(at.run)
    assert not at.exception, at.exception
    assert run.stall < STALL_LIMIT_S * 0.8, run


@pytest.mark.parametrize("safeguards,flags", [
    ("not a report", 5),
    ({"status": "on", "checks": "abc", "counts": 7}, {"code": "x"}),
    ({"status": "on", "checks": [None, 3, {"status": "modified", "excerpt": "<script>x</script>",
                                           "reason": "<b>r</b>", "rail_set": "retrieved"}]},
     [None, {"sentence": "<b>flag</b>", "threat_id": 'TC-S01"><x'}]),
])
def test_an_imported_record_with_odd_safeguards_fields_opens(safeguards: object, flags: object) -> None:
    payload = mock_payload()
    payload["safeguards"] = safeguards
    payload["review_flags"] = flags
    source = Workspace()
    source.add(RecordKind.THREAT_MODELS, "Imported", payload)
    workspace = Workspace.from_json(json.dumps(source.to_dict()).encode())
    (record,) = workspace.list(RecordKind.THREAT_MODELS)
    at = AppTest.from_function(_app, default_timeout=60)
    at.session_state["aegis_workspace"] = workspace
    at.query_params["id"] = record.id
    at.run()
    assert not at.exception, at.exception
