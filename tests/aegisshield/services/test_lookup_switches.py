"""Every lookup source answers to the offline switch and its own flag."""

from __future__ import annotations

import pytest

from aegisshield.config import Settings
from aegisshield.services.lookup_switches import SOURCE_FLAGS, source_disabled


@pytest.mark.parametrize("source", sorted(SOURCE_FLAGS))
def test_each_source_has_the_source_flag_name(source) -> None:
    assert SOURCE_FLAGS[source] == f"AEGIS_DISABLE_{source.upper()}"
    assert source_disabled(source, env={}) is False
    assert source_disabled(source, env={SOURCE_FLAGS[source]: "1"}) is True
    assert source_disabled(source, env={"AEGIS_OFFLINE": "yes"}) is True
    assert source_disabled(source, Settings(offline=True), env={}) is True


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " on "])
def test_every_flag_accepts_the_same_values(value) -> None:
    # ExploitDB and endoflife.date accept every true spelling too, not only "1".
    for source, flag in SOURCE_FLAGS.items():
        assert source_disabled(source, env={flag: value}) is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "2"])
def test_other_values_leave_the_source_on(value) -> None:
    for source, flag in SOURCE_FLAGS.items():
        assert source_disabled(source, env={flag: value}) is False


def test_mock_llm_does_not_switch_sources_off() -> None:
    for source in SOURCE_FLAGS:
        assert source_disabled(source, Settings(mock_llm=True), env={}) is False


def test_an_unknown_source_is_an_error() -> None:
    with pytest.raises(ValueError):
        source_disabled("shodan", env={})


def test_reads_the_process_environment_by_default(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_DISABLE_OTX", "1")
    assert source_disabled("otx") is True
    monkeypatch.delenv("AEGIS_DISABLE_OTX")
    monkeypatch.delenv("AEGIS_OFFLINE", raising=False)
    assert source_disabled("otx") is False
