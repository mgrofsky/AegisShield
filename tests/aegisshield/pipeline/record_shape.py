"""Structural checks for the progress record, shared by the contract tests.

The page's live view consumes exactly this shape, so these checks are written
once and run against the recorded run in the fixtures and against what this
repo's pipeline writes. Each ``check_*`` raises ``AssertionError`` with the
path of the first thing out of shape.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

STAGE_IDS = [
    "serialize",
    "nvd",
    "otx",
    "stride",
    "mitre_load",
    "mitre_map",
    "attack_tree",
    "markdown",
    "mitigations",
    "dread",
    "test_cases",
]
STAGE_KEYS = {
    "id",
    "label",
    "phase",
    "name",
    "term",
    "status",
    "detail",
    "reason",
    "started_s",
    "finished_s",
}
STATUSES = {"queued", "working", "done", "fallback", "error"}
PHASES = {"enrichment", "modeling", "scoring", "validation"}
OFFICE_KEYS = {"office", "stages", "step", "total", "current"}
DECK_KEYS = {
    "v",
    "t",
    "threats",
    "techniques",
    "tree",
    "fixes",
    "scores",
    "tests",
    "live",
    "unmatched",
    "truncated",
}
SCORE_KEYS = {
    "risk",
    "damage",
    "reproducibility",
    "exploitability",
    "affected_users",
    "discoverability",
    "t",
}
NVD_ENTRY_KEYS = {"tech", "version", "state", "returned", "used", "top", "t"}
NVD_TOTAL_KEYS = {"checked", "returned", "used", "failed", "unknown"}
OTX_KEYS = {"sector", "state", "returned", "used", "at_least", "reports", "t"}
AGENT_KEYS = {
    "id",
    "role",
    "section",
    "status",
    "activity",
    "started_at",
    "finished_at",
    "findings",
}


def load_json(name: str) -> Any:
    """A fixture under ``tests/fixtures`` (``.gz`` files are decompressed)."""
    path = FIXTURES / name
    raw = gzip.decompress(path.read_bytes()) if name.endswith(".gz") else path.read_bytes()
    return json.loads(raw)


def _is_num(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 9999


def _opt_num(value: object) -> bool:
    return value is None or _is_num(value)


def _opt_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _keys(where: str, obj: object, expected: set[str], optional: set[str] = frozenset()) -> None:
    assert isinstance(obj, dict), f"{where}: not an object"
    keys = set(obj)
    assert expected <= keys <= expected | optional, f"{where}: keys {sorted(keys)}"


def check_stage(where: str, stage: object) -> None:
    """One entry of ``stages``."""
    _keys(where, stage, STAGE_KEYS)
    assert stage["status"] in STATUSES, f"{where}.status"
    assert stage["phase"] in PHASES, f"{where}.phase"
    for key in ("label", "name", "term"):
        assert isinstance(stage[key], str) and stage[key], f"{where}.{key}"
    for key in ("detail", "reason"):
        assert _opt_str(stage[key]), f"{where}.{key}"
    for key in ("started_s", "finished_s"):
        assert _opt_num(stage[key]), f"{where}.{key}"
    if stage["status"] == "queued":
        assert stage["started_s"] is None and stage["finished_s"] is None, f"{where}: queued times"
    if stage["status"] in {"done", "fallback", "error"}:
        assert _is_num(stage["finished_s"]), f"{where}: resolved without finished_s"


def check_lookups(where: str, lookups: object) -> None:
    """The ``lookups`` part of a deck."""
    _keys(where, lookups, {"nvd", "nvd_more", "nvd_total", "otx"})
    assert isinstance(lookups["nvd"], list), f"{where}.nvd"
    for i, entry in enumerate(lookups["nvd"]):
        at = f"{where}.nvd[{i}]"
        _keys(at, entry, NVD_ENTRY_KEYS)
        assert entry["state"] in {"found", "none", "unknown", "failed"}, f"{at}.state"
        assert isinstance(entry["tech"], str) and isinstance(entry["version"], str), at
        assert _is_count(entry["returned"]) and _is_count(entry["used"]), at
        assert _is_num(entry["t"]), f"{at}.t"
        assert isinstance(entry["top"], list) and len(entry["top"]) <= 5, f"{at}.top"
        for item in entry["top"]:
            _keys(f"{at}.top", item, {"id", "score"})
            assert isinstance(item["id"], str) and item["id"].startswith("CVE-"), f"{at}.top.id"
            assert _opt_num(item["score"]), f"{at}.top.score"
    assert _is_count(lookups["nvd_more"]), f"{where}.nvd_more"
    _keys(f"{where}.nvd_total", lookups["nvd_total"], NVD_TOTAL_KEYS)
    assert all(_is_count(v) for v in lookups["nvd_total"].values()), f"{where}.nvd_total"
    otx = lookups["otx"]
    if otx is None:
        return
    _keys(f"{where}.otx", otx, OTX_KEYS)
    assert otx["state"] in {"found", "none", "failed", "off"}, f"{where}.otx.state"
    assert isinstance(otx["sector"], str), f"{where}.otx.sector"
    assert _is_count(otx["returned"]) and _is_count(otx["used"]), f"{where}.otx counts"
    assert isinstance(otx["at_least"], bool), f"{where}.otx.at_least"
    assert _is_num(otx["t"]), f"{where}.otx.t"
    assert isinstance(otx["reports"], list) and len(otx["reports"]) <= 10, f"{where}.otx.reports"
    for report in otx["reports"]:
        _keys(f"{where}.otx.reports", report, {"title", "date"})
        assert isinstance(report["title"], str) and _opt_str(report["date"]), where


def check_deck(where: str, deck: object) -> None:
    """A ``deck`` record at version 1."""
    _keys(where, deck, DECK_KEYS, {"lookups"})
    assert deck["v"] == 1, f"{where}.v"
    assert _is_num(deck["t"]), f"{where}.t"
    assert isinstance(deck["truncated"], bool), f"{where}.truncated"
    ids = set()
    for i, threat in enumerate(deck["threats"]):
        _keys(f"{where}.threats[{i}]", threat, {"id", "type", "scenario", "t"})
        assert isinstance(threat["scenario"], str) and isinstance(threat["type"], str), where
        assert len(threat["scenario"]) <= 600 and len(threat["type"]) <= 40, where
        ids.add(threat["id"])
    for tid, tech in deck["techniques"].items():
        _keys(f"{where}.techniques.{tid}", tech, {"id", "name", "t"})
        assert tid in ids, f"{where}.techniques: {tid} is not a deck threat"
    _keys(f"{where}.tree", deck["tree"], {"root", "links", "steps"})
    assert _opt_str(deck["tree"]["root"]) and _is_count(deck["tree"]["links"]), where
    assert set(deck["tree"]["steps"]) <= ids, f"{where}.tree.steps"
    for tid, fix in deck["fixes"].items():
        _keys(f"{where}.fixes.{tid}", fix, {"text", "t"})
        assert tid in ids and len(fix["text"]) <= 300, f"{where}.fixes.{tid}"
    for tid, score in deck["scores"].items():
        _keys(f"{where}.scores.{tid}", score, SCORE_KEYS)
        assert tid in ids, f"{where}.scores.{tid}"
    for tid, test in deck["tests"].items():
        _keys(f"{where}.tests.{tid}", test, {"title", "t"})
        assert tid in ids and len(test["title"]) <= 200, f"{where}.tests.{tid}"
    _keys(f"{where}.unmatched", deck["unmatched"], {"fixes", "scores", "tests", "tree"})
    live = deck["live"]
    if live is not None:
        optional = {"field"} if live.get("stage") == "stride" else set()
        _keys(f"{where}.live", live, {"stage", "item", "text"} | optional)
        assert live["stage"] in STAGE_IDS, f"{where}.live.stage"
        assert _opt_str(live["item"]) and len(live["text"]) <= 400, f"{where}.live"
    if "lookups" in deck:
        check_lookups(f"{where}.lookups", deck["lookups"])


def check_office(where: str, record: object) -> None:
    """A linear-path progress record: the office frame and its deck."""
    _keys(where, record, OFFICE_KEYS, {"deck"})
    assert record["office"] is True, f"{where}.office"
    stages = record["stages"]
    assert [s.get("id") for s in stages] == STAGE_IDS, f"{where}.stages ids"
    for i, stage in enumerate(stages):
        check_stage(f"{where}.stages[{i}]", stage)
    assert record["total"] in (8, 11), f"{where}.total"
    assert _is_count(record["step"]) and record["step"] <= record["total"], f"{where}.step"
    assert isinstance(record["current"], str), f"{where}.current"
    details = [s["detail"] for s in stages if s["detail"] is not None]
    assert len(details) <= 1, f"{where}: detail on more than one stage"
    if details:
        assert next(s for s in stages if s["detail"] is not None)["id"] == record["current"]
    if "deck" in record:
        check_deck(f"{where}.deck", record["deck"])


def check_agentic(where: str, record: object) -> None:
    """An agentic-path progress record: the Lead and the agent roster."""
    _keys(where, record, {"step", "total", "current", "agentic", "lead", "agents"})
    assert record["agentic"] is True, f"{where}.agentic"
    _keys(f"{where}.lead", record["lead"], {"status", "note"})
    assert isinstance(record["lead"]["note"], str), f"{where}.lead.note"
    for i, agent in enumerate(record["agents"]):
        _keys(f"{where}.agents[{i}]", agent, AGENT_KEYS)
        assert agent["status"] in {"queued", "working", "done", "fallback", "error"}, where
