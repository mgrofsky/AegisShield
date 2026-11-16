"""The ``deck`` in a threat-model job's progress record.

The deck is display data for the live "agents at work" view: threats as they
are written, then each threat's technique, attack-path steps, fix, risk score,
and test. Streamed text fills it early; when a stage finishes, that stage's
part is rebuilt from the final parsed result, so at stage end the deck equals
the result. Nothing in the job's ``result`` is read from here.

Every string is model or user text and is capped in length. No prompt text,
keys, model ids, or exception text goes into the deck.

Pure standard library plus the pure formatting and DREAD helpers.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from datetime import date
from typing import Any

from aegisshield.core.text import clip_tail, clip_words, single_line
from aegisshield.pipeline.dread_service import _extract_id
from aegisshield.pipeline.formatting_service import _stride_letter
from aegisshield.pipeline.stream_items import (
    JsonArrayItems,
    Lines,
    Sections,
    TableRows,
)

DECK_VERSION = 1

CAP_SCENARIO = 600
CAP_FIX = 300
CAP_TEST_TITLE = 200
CAP_LIVE_TEXT = 400
CAP_TECHNIQUE_NAME = 120
CAP_TYPE = 40
CAP_REASON = 160
CAP_TREE_ROOT = 160

# What the threat writer's ``live.field`` can name.
STRIDE_FIELDS = ("Scenario", "Potential Impact")
SUGGESTIONS_FIELD = "Recommendations"

# Bounds on what the deck holds (display only; ``result`` is never capped).
MAX_THREATS = 200
MAX_COUNT = 9999

# What the lookups gave (``lookups``): display only, never read by the prompt.
MAX_LOOKUP_TECHS = 25
MAX_LOOKUP_IDS = 5
MAX_LOOKUP_REPORTS = 10
CAP_LOOKUP_TECH = 60
CAP_LOOKUP_VERSION = 30
CAP_LOOKUP_SECTOR = 60
CAP_LOOKUP_TITLE = 120
# ``unknown``: NVD has no entry for the product and version (an answer).
NVD_STATES = ("found", "none", "unknown", "failed")
NVD_TOTALS = ("checked", "returned", "used", "failed", "unknown")
OTX_STATES = ("found", "none", "failed", "off")
# ASCII digits only: ``\d`` would also take full-width and other scripts' digits.
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})(?:T.*)?", re.DOTALL)

_ITEM_TAIL = 4000
_RAW_TAIL = 2000

# A threat id inside model text, and the exact shape every deck id must have.
_TC_RE = re.compile(r"TC-[A-Z]\d{2,4}(?!\d)")
_TC_ID_RE = re.compile(r"TC-[A-Z]\d{2,4}")
# Any label that looks like a threat node, so a malformed id counts as unmatched.
_TC_NODE_RE = re.compile(r"TC-[A-Za-z]\d+")
_THREAT_TYPE_RE = re.compile(r'"Threat Type"\s*:\s*"((?:[^"\\]|\\.)*)"')
# Arrow tokens only: whitespace and ``|label|`` are trimmed with string
# methods after the split, so no pattern holds an unbounded whitespace group.
_ARROWS = ("-->", "-.->", "==>", "---")
_ARROW_RE = re.compile("|".join(re.escape(arrow) for arrow in _ARROWS))
_MAX_TREE_LINE = 2000
_NODE_RE = re.compile(r"^([A-Za-z0-9_]+)(.*)$")
_SCENARIO_RE = re.compile(r"^\s*Scenario(?: Outline)?:\s*(.*)$")
_FEATURE_RE = re.compile(r"^\s*Feature:\s*(.*)$")
_TREE_SKIP = ("%%", "graph ", "flowchart ", "```", "classDef ", "class ", "style ", "linkStyle ", "subgraph ")


def valid_id(value: object) -> bool:
    """True when ``value`` is a threat id the deck may store or show."""
    return isinstance(value, str) and _TC_ID_RE.fullmatch(value) is not None


def lookup_text(value: object, limit: int) -> str:
    """A lookup string: newline and tab read as a space; bidirectional,
    invisible, C0, and C1 controls gone; clipped on a word."""
    return single_line(value, limit)


def cve_id(value: object) -> str | None:
    """``value`` when it is exactly a CVE id, else None."""
    return value if isinstance(value, str) and _CVE_RE.fullmatch(value) else None


def cvss(value: object) -> float | None:
    """The score in nvdlib's list-shaped value (``['V31', 8.8, 'HIGH']``) or a
    bare number, when it is a finite number from 0 to 10; else None."""
    if isinstance(value, (list, tuple)):
        value = next((v for v in value if isinstance(v, (int, float)) and not isinstance(v, bool)), None)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None  # an integer too large for a float is not a 0 to 10 score
    return number if math.isfinite(number) and 0 <= number <= 10 else None


def iso_date(value: object) -> str | None:
    """``YYYY-MM-DD`` from a date or timestamp string, or None."""
    if not isinstance(value, str):
        return None
    match = _DATE_RE.fullmatch(value)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1)).isoformat()
    except ValueError:
        return None


def lookup_count(value: object) -> int:
    """A count from a lookup: a whole number from 0 to ``MAX_COUNT``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if isinstance(value, float) and not math.isfinite(value):
        return 0
    # compared, never converted, so an integer of any size is safe
    if value < 0:
        return 0
    return MAX_COUNT if value >= MAX_COUNT else int(value)


def _round_t(value: float) -> float:
    return round(float(value), 1)


def _label(rest: str) -> str:
    text = rest.strip()
    text = text.lstrip("[({>").rstrip("])}").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text.strip()


class _TreeCounter:
    """Counts edges, the root label, and each threat node's direct children."""

    def __init__(self) -> None:
        self.links = 0
        self.root: str | None = None
        self.last_threat: str | None = None
        self._node_threat: dict[str, str] = {}
        self._children: dict[str, set[str]] = {}

    def line(self, raw: str) -> None:
        if len(raw) > _MAX_TREE_LINE:
            return
        line = raw.strip()
        if not line or line == "end" or line.startswith(_TREE_SKIP):
            return
        segments = _ARROW_RE.split(line)
        nodes: list[str] = []
        for index, segment in enumerate(segments):
            segment = segment.strip()
            if index and segment.startswith("|"):
                close = segment.find("|", 1)
                segment = segment[close + 1 :].strip() if close > 0 else segment
            match = _NODE_RE.match(segment)
            if not match:
                nodes.append("")
                continue
            node, rest = match.group(1), match.group(2)
            nodes.append(node)
            # A Mermaid label always opens with a bracket; bare prose is not a node.
            label = _label(rest) if rest.strip()[:1] in ("[", "(", "{", ">") else ""
            if label and self.root is None:
                self.root = label
            tc = _TC_NODE_RE.match(label) if label else None
            if tc:
                self._node_threat[node] = tc.group(0)
                self._children.setdefault(tc.group(0), set())
                self.last_threat = tc.group(0)
        for src, dst in zip(nodes, nodes[1:], strict=False):
            if not src or not dst:
                continue
            self.links += 1
            threat = self._node_threat.get(src)
            if threat:
                self._children[threat].add(dst)
                self.last_threat = threat

    def snapshot(self) -> dict[str, Any]:
        return {
            "root": clip_words(self.root, CAP_TREE_ROOT) if self.root else None,
            "links": min(self.links, MAX_COUNT),
            "steps": {tid: min(len(kids), MAX_COUNT) for tid, kids in self._children.items()},
        }


def _fix_from_row(cells: list[str]) -> tuple[str | None, str]:
    match = _TC_RE.search(cells[0]) if cells else None
    text = " | ".join(c for c in cells[1:] if c)
    return (match.group(0) if match else None), clip_words(text, CAP_FIX)


_AXES = ("Damage Potential", "Reproducibility", "Exploitability", "Affected Users", "Discoverability")


def _score_from_item(item: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Same id rule and arithmetic as ``dread_service.dread_json_to_markdown``.

    The deck is stricter than the result: every axis must be a whole number
    from 1 to 10 (not a bool, float, or string), or the item is not stored.
    """
    values = [item.get(axis) for axis in _AXES]
    if not all(type(v) is int and 1 <= v <= 10 for v in values):
        return None
    damage, reproducibility, exploitability, affected, discoverability = values
    risk = (damage + reproducibility + exploitability + affected + discoverability) / 5
    return _extract_id(item), {
        "risk": risk,
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected,
        "discoverability": discoverability,
    }


def _test_title(body: str) -> str:
    feature = ""
    for line in body.splitlines():
        scenario = _SCENARIO_RE.match(line)
        if scenario:
            return clip_words(scenario.group(1), CAP_TEST_TITLE)
        found = _FEATURE_RE.match(line)
        if found and not feature:
            feature = found.group(1)
    return clip_words(feature, CAP_TEST_TITLE)


class LiveDeck:
    """Builds the ``deck`` dict. ``now`` returns seconds since the run started."""

    def __init__(self, now: Callable[[], float]) -> None:
        self._now = now
        self.threats: list[dict[str, Any]] = []
        self.techniques: dict[str, dict[str, Any]] = {}
        self.tree: dict[str, Any] = {"root": None, "links": 0, "steps": {}}
        self.fixes: dict[str, dict[str, Any]] = {}
        self.scores: dict[str, dict[str, Any]] = {}
        self.tests: dict[str, dict[str, Any]] = {}
        self.live: dict[str, Any] | None = None
        self.unmatched = {"fixes": 0, "scores": 0, "tests": 0, "tree": 0}
        self.truncated = False
        self.lookups: dict[str, Any] | None = None
        self._seen: dict[tuple[str, str], float] = {}

    # helpers

    def _t(self, part: str, key: str) -> float:
        """First-seen time for ``part``/``key``; set now when new."""
        return self._seen.setdefault((part, key), _round_t(self._now()))

    def threat_ids(self) -> set[str]:
        return {t["id"] for t in self.threats}

    def set_live(self, stage: str, item: str | None, text: str, field: str | None = None) -> None:
        """``field`` (the plain name of the value being written) is kept for
        the threat writer only; other stages' ``live`` has no such key."""
        self.live = {
            "stage": stage,
            "item": item if valid_id(item) else None,
            "text": clip_tail(text or "", CAP_LIVE_TEXT),
        }
        if stage == "stride":
            self.live["field"] = field

    def clear_live(self) -> None:
        self.live = None

    def as_dict(self) -> dict[str, Any]:
        out = {
            "v": DECK_VERSION,
            "t": _round_t(self._now()),
            "threats": [dict(t) for t in self.threats],
            "techniques": {k: dict(v) for k, v in self.techniques.items()},
            "tree": {**self.tree, "steps": dict(self.tree["steps"])},
            "fixes": {k: dict(v) for k, v in self.fixes.items()},
            "scores": {k: dict(v) for k, v in self.scores.items()},
            "tests": {k: dict(v) for k, v in self.tests.items()},
            "live": dict(self.live) if self.live else None,
            "unmatched": dict(self.unmatched),
            "truncated": self.truncated,
        }
        if self.lookups is not None:
            lookups = self.lookups
            otx = lookups["otx"]
            out["lookups"] = {
                "nvd": [{**e, "top": [dict(i) for i in e["top"]]} for e in lookups["nvd"]],
                "nvd_more": lookups["nvd_more"],
                "nvd_total": dict(lookups["nvd_total"]),
                "otx": {**otx, "reports": [dict(r) for r in otx["reports"]]} if otx else None,
            }
        return out

    # lookups (NVD, OTX)

    def _lookups(self) -> dict[str, Any]:
        if self.lookups is None:
            self.lookups = {"nvd": [], "nvd_more": 0, "nvd_total": dict.fromkeys(NVD_TOTALS, 0), "otx": None}
        return self.lookups

    def add_nvd_lookup(
        self,
        tech: object,
        version: object,
        state: str,
        returned: object,
        used: object,
        top: list[tuple[object, object]],
    ) -> None:
        """One technology's answer. ``top`` is (id, score as given) in the
        order the prompt lists them; the first five valid ids are kept. The
        running totals count every technology, listed or not."""
        lookups = self._lookups()
        state = state if state in NVD_STATES else "failed"
        returned = lookup_count(returned)
        used = lookup_count(used)
        total = lookups["nvd_total"]
        for key, add in (("checked", 1), ("returned", returned), ("used", used)):
            total[key] = min(total[key] + add, MAX_COUNT)
        if state in ("failed", "unknown"):
            total[state] = min(total[state] + 1, MAX_COUNT)
        if len(lookups["nvd"]) >= MAX_LOOKUP_TECHS:
            lookups["nvd_more"] = min(lookups["nvd_more"] + 1, MAX_COUNT)
            return
        ids = [{"id": cve_id(i), "score": cvss(score)} for i, score in top if cve_id(i)]
        lookups["nvd"].append(
            {
                "tech": lookup_text(tech, CAP_LOOKUP_TECH),
                "version": lookup_text(version, CAP_LOOKUP_VERSION),
                "state": state,
                "returned": returned,
                "used": used,
                "top": ids[:MAX_LOOKUP_IDS],
                "t": _round_t(self._now()),
            }
        )

    def set_otx_lookup(
        self,
        sector: object,
        state: str,
        returned: object,
        used: object,
        reports: list[tuple[object, object]],
        at_least: bool = False,
    ) -> None:
        """The OTX answer. ``reports`` is (title, modified) for each kept
        report. ``at_least``: the search hit its limit, so ``returned`` is a floor."""
        self._lookups()["otx"] = {
            "sector": lookup_text(sector, CAP_LOOKUP_SECTOR),
            "state": state if state in OTX_STATES else "failed",
            "returned": lookup_count(returned),
            "used": lookup_count(used),
            "at_least": at_least is True,
            "reports": [
                {"title": lookup_text(title, CAP_LOOKUP_TITLE), "date": iso_date(modified)}
                for title, modified in reports[:MAX_LOOKUP_REPORTS]
            ],
            "t": _round_t(self._now()),
        }

    def _threat_entry(self, tid: str, threat: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": tid,
            "type": clip_words(str(threat.get("Threat Type") or ""), CAP_TYPE),
            "scenario": clip_words(str(threat.get("Scenario") or ""), CAP_SCENARIO),
            "t": self._t("threats", tid),
        }

    # threats (STRIDE)

    def add_threat(self, tid: str, threat: dict[str, Any]) -> None:
        if not valid_id(tid):
            return
        known = tid in self.threat_ids()
        if not known and len(self.threats) >= MAX_THREATS:
            self.truncated = True
            return
        entry = self._threat_entry(tid, threat)
        self.threats = [t for t in self.threats if t["id"] != tid] + [entry]

    def final_threats(self, threat_model: list[dict[str, Any]]) -> None:
        self.threats = []
        self.truncated = False
        for threat in threat_model:
            if isinstance(threat, dict) and threat.get("ID"):
                self.add_threat(str(threat.get("ID")), threat)

    # techniques (MITRE mapping)

    def add_technique(self, tid: str, technique: dict[str, Any] | None) -> None:
        if not technique or tid not in self.threat_ids():
            return
        self.techniques[tid] = {
            "id": clip_words(str(technique.get("technique_id") or ""), CAP_TECHNIQUE_NAME),
            "name": clip_words(str(technique.get("name") or ""), CAP_TECHNIQUE_NAME),
            "t": self._t("techniques", tid),
        }

    def final_techniques(self, mitre_data: list[dict[str, Any]]) -> None:
        self.techniques = {}
        for entry in mitre_data or []:
            tid = str((entry.get("threat") or {}).get("ID") or "")
            techniques = entry.get("mitre_techniques") or []
            self.add_technique(tid, techniques[0] if techniques else None)

    # attack tree

    def set_tree(self, counter: _TreeCounter) -> None:
        """Store the counts; steps only for threats in the deck."""
        snapshot = counter.snapshot()
        known = self.threat_ids()
        steps = snapshot["steps"]
        snapshot["steps"] = {tid: n for tid, n in steps.items() if tid in known}
        self.unmatched["tree"] = len(steps) - len(snapshot["steps"])
        self.tree = snapshot

    def final_tree(self, code: str) -> None:
        counter = _TreeCounter()
        for line in (code or "").split("\n"):
            counter.line(line)
        self.set_tree(counter)

    # add-ons

    def drop_addon(self, stage_id: str) -> None:
        """Remove a failed add-on's streamed items, so the deck never shows
        items the result does not contain."""
        part = {"mitigations": "fixes", "dread": "scores", "test_cases": "tests"}[stage_id]
        setattr(self, part, {})
        self.unmatched[part] = 0
        self._seen = {key: t for key, t in self._seen.items() if key[0] != part}
        self.live = None

    def drop_stream(self, stage: str) -> None:
        """Remove what one stage's stream added, after its answer was withheld
        or its call failed, so the deck never shows an answer the run did not
        accept. Only the threat writer, the attack tree, and the add-ons stream."""
        if stage == "stride":
            self.threats = []
            self.truncated = False
            self._seen = {key: t for key, t in self._seen.items() if key[0] != "threats"}
        elif stage in ("mitigations", "dread", "test_cases"):
            self.drop_addon(stage)
        else:
            self.tree = {"root": None, "links": 0, "steps": {}}
            self.unmatched["tree"] = 0
        self.live = None

    # fixes (mitigations)

    def add_fix(self, cells: list[str]) -> None:
        tid, text = _fix_from_row(cells)
        if not valid_id(tid) or tid not in self.threat_ids():
            self.unmatched["fixes"] += 1
            return
        self.fixes[tid] = {"text": text, "t": self._t("fixes", tid)}

    def final_fixes(self, markdown: str) -> None:
        self.fixes = {}
        self.unmatched["fixes"] = 0
        parser = TableRows()
        for row in [*parser.feed(markdown or ""), *parser.close()]:
            self.add_fix(row)

    # scores (DREAD)

    def add_score(self, item: dict[str, Any]) -> None:
        scored = _score_from_item(item)
        if scored is None or not valid_id(scored[0]) or scored[0] not in self.threat_ids():
            self.unmatched["scores"] += 1
            return
        tid, values = scored
        self.scores[tid] = {**values, "t": self._t("scores", tid)}

    def final_scores(self, dread_assessment: dict[str, Any]) -> None:
        self.scores = {}
        self.unmatched["scores"] = 0
        items = (dread_assessment or {}).get("Risk Assessment") or []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                self.add_score(item)

    # tests (test cases)

    def add_test(self, section: dict[str, str]) -> None:
        match = _TC_RE.search(section.get("heading") or "")
        tid = match.group(0) if match else None
        if not valid_id(tid) or tid not in self.threat_ids():
            self.unmatched["tests"] += 1
            return
        self.tests[tid] = {
            "title": _test_title(section.get("body") or ""),
            "t": self._t("tests", tid),
        }

    def final_tests(self, markdown: str) -> None:
        self.tests = {}
        self.unmatched["tests"] = 0
        parser = Sections()
        for section in [*parser.feed(markdown or ""), *parser.close()]:
            self.add_test(section)


class StageStream:
    """Feeds one stage's streamed text into the deck and the ``live`` panel.

    ``changed`` is called after every delta so the emitter can coalesce writes.
    """

    def __init__(self, stage: str, deck: LiveDeck, changed: Callable[[], None]) -> None:
        self.stage = stage
        self._deck = deck
        self._changed = changed
        self._reset()

    def _reset(self) -> None:
        """The parsing state for a new answer."""
        stage = self.stage
        self._raw = ""
        self._counts: dict[str, int] = {}
        self._tree = _TreeCounter()
        # Threat id by array position, as each STRIDE item completes.
        self._ids: dict[int, str] = {}
        self._parser: Any
        if stage == "stride":
            self._parser = JsonArrayItems(
                "threat_model",
                fields=STRIDE_FIELDS,
                list_key="improvement_suggestions",
                list_label=SUGGESTIONS_FIELD,
            )
        elif stage == "dread":
            self._parser = JsonArrayItems("Risk Assessment")
        elif stage == "mitigations":
            self._parser = TableRows()
        elif stage == "test_cases":
            self._parser = Sections()
        else:
            self._parser = Lines()

    def retract(self) -> None:
        """Drop what this stream showed and start over (the answer was
        withheld or its call failed)."""
        self._deck.drop_stream(self.stage)
        self._reset()
        self._changed()

    def __call__(self, delta: str) -> None:
        self._raw = (self._raw + delta)[-_RAW_TAIL:]
        items = self._parser.feed(delta)
        ordinals = getattr(self._parser, "last_ordinals", [])
        for index, item in enumerate(items):
            self._item(item, ordinals[index] if index < len(ordinals) else None)
        self._update_live()
        self._changed()

    def _next_id(self, threat_type: str, commit: bool) -> str:
        letter = _stride_letter(threat_type)
        seq = self._counts.get(letter, 0) + 1
        if commit:
            self._counts[letter] = seq
        return f"TC-{letter}{seq:02d}"

    def _item(self, item: Any, ordinal: int | None) -> None:
        if self.stage == "stride":
            tid = self._next_id(str(item.get("Threat Type", "")), True)
            if ordinal is not None:
                self._ids[ordinal] = tid
            self._deck.add_threat(tid, item)
        elif self.stage == "dread":
            self._deck.add_score(item)
        elif self.stage == "mitigations":
            self._deck.add_fix(item)
        elif self.stage == "test_cases":
            self._deck.add_test(item)
        else:
            self._tree.line(item)
            self._deck.set_tree(self._tree)

    def _stride_item(self, ordinal: int | None, item_text: str) -> str | None:
        """Threat id of the item at ``ordinal``: final once it completed,
        provisional (from its Threat Type) while it is being written."""
        if ordinal is None:
            return None
        if ordinal in self._ids:
            return self._ids[ordinal]
        if ordinal != self._parser.items_started - 1 or not self._parser.in_item:
            return None
        match = _THREAT_TYPE_RE.search(item_text)
        return self._next_id(match.group(1), False) if match else None

    def _update_live(self) -> None:
        item_text = self._parser.tail(_ITEM_TAIL)
        item: str | None = None
        if self.stage == "stride":
            # The plain text of the field being written, never raw JSON. While
            # no field is being written, the last field's text and threat stay.
            parser = self._parser
            if parser.has_field:
                item = self._stride_item(parser.field_ordinal, item_text)
                text = parser.field_text
            else:
                item = self._stride_item(parser.items_started - 1, item_text)
                text = ""
            self._deck.set_live(self.stage, item, text, parser.field)
            return
        if self.stage == "test_cases":
            heading = self._parser.heading
            match = _TC_RE.search(heading) if heading else None
            item = match.group(0) if match else None
        elif self.stage in ("dread", "mitigations"):
            match = _TC_RE.search(item_text)
            item = match.group(0) if match else None
        else:
            item = self._tree.last_threat
        self._deck.set_live(self.stage, item, item_text or self._raw)
