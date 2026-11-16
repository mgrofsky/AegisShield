"""The evaluation harness (``tools/safeguard_eval.py``) and its NeMo replay.

The drift test reruns the harness on the committed cases and compares what it
produces with the committed results, so the documentation cannot drift from
the code. Timings, the date, and the commit are not compared: they change
from run to run. Everything else is deterministic (the stand-in, the stubbed
lookups, and the fake ``tshark`` answer the same way every time).
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from aegisshield.llm.susceptible import SusceptibleLLM
from tools import nemo_replay
from tools import safeguard_eval as ev

ROOT = Path(__file__).resolve().parents[3]
COMMITTED = ROOT / "docs" / "ai-safeguards" / "results"


def _strip(results: dict[str, Any]) -> dict[str, Any]:
    """The deterministic part of results.json: no stamp, no timings."""
    out = {k: v for k, v in results.items() if k != "stamp"}
    out["cases"] = [{k: v for k, v in row.items() if k != "seconds"} for row in results["cases"]]
    return out


@pytest.fixture(scope="module")
def fresh(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("eval")
    assert ev.main(["--out", str(out)], stdout=io.StringIO()) == 0
    return out


def test_the_committed_table_matches_what_the_harness_produces(fresh: Path) -> None:
    committed = (COMMITTED / "table.md").read_text(encoding="utf-8")
    produced = (fresh / "table.md").read_text(encoding="utf-8")
    assert ev.deterministic_part(produced) == ev.deterministic_part(committed)


def test_the_committed_results_match_what_the_harness_produces(fresh: Path) -> None:
    committed = json.loads((COMMITTED / "results.json").read_text(encoding="utf-8"))
    produced = json.loads((fresh / "results.json").read_text(encoding="utf-8"))
    assert _strip(produced) == _strip(committed)


def test_every_committed_file_says_the_model_was_the_stand_in() -> None:
    table = (COMMITTED / "table.md").read_text(encoding="utf-8")
    assert table.splitlines()[2] == f"> {ev.SIMULATED_NOTE}"
    stamp = json.loads((COMMITTED / "results.json").read_text(encoding="utf-8"))["stamp"]
    assert stamp["note"] == ev.SIMULATED_NOTE and stamp["model"] == "simulated stand-in"
    assert {"date", "commit", "python", "nemo_guardrails", "garak"} <= set(stamp)


def test_every_committed_results_file_says_what_the_model_was() -> None:
    """Each table opens with the stand-in note; each JSON file carries it and a stamp."""
    files = sorted(p for p in COMMITTED.rglob("*") if p.is_file())
    assert files
    for path in files:
        if path.suffix == ".md":
            head = path.read_text(encoding="utf-8").splitlines()[:4]
            assert any(line.startswith("> Model: the simulated stand-in") for line in head), path
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
            note = data.get("note") or data["stamp"]["note"]
            assert "simulated stand-in" in note, path
            assert {"date", "commit", "python", "nemo_guardrails", "garak"} <= set(data["stamp"]), path
            assert data["stamp"]["commit"] == ev.COMMIT_NOTE, path


def test_no_committed_results_file_names_a_commit_id() -> None:
    """The branch is squashed before it is published, so a commit id would
    point at nothing; the files name "the commit that added these files"."""
    import re

    for path in sorted(p for p in COMMITTED.rglob("*") if p.is_file()):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\bcommit\W{1,4}[0-9a-f]{7,40}\b", text), path
    doc = (ROOT / "docs" / "ai-safeguards.md").read_text(encoding="utf-8")
    assert not re.search(r"\bcommit\W{1,4}[0-9a-f]{7,40}\b|\| [0-9a-f]{7,40} \|", doc)


def test_the_stamp_names_no_commit_id() -> None:
    assert ev.stamp(real=False)["commit"] == ev.COMMIT_NOTE
    assert ev.COMMIT_NOTE == "the commit that added these files"


def test_the_cases_cover_every_entry_and_risk() -> None:
    cases = ev.load_cases()
    attacks = [c for c in cases if c.kind == "attack" and not c.hard]
    entries = {"description", "diagram", "capture", "nvd", "otx", "pasted_list", "profile", "import"}
    assert entries <= {c.surface for c in attacks}
    assert {"hidden_instruction", "expose", "disregard"} == {c.risk for c in attacks}
    assert len({c.id for c in cases}) == len(cases)
    assert any(c.hard and c.kind == "ordinary" for c in cases) and any(c.hard and c.kind == "attack" for c in cases)


def test_bad_cases_and_rules_are_refused(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"id": "x", "kind": "attack", "surface": "elsewhere", "text": "t"}) + "\n\n")
    with pytest.raises(ValueError):
        ev.load_cases(bad)
    with pytest.raises(ValueError):
        ev.resolve("nowhere:x")
    case = ev.Case("x", "attack", "otx", "t", False, "")
    with pytest.raises(ValueError):
        ev.had_effect(case, ev.Outcome("output", None, {}, [], 0.0))
    assert ev.had_effect(case, ev.Outcome("", None, {}, [], 0.0)) is False


def test_a_blocked_ordinary_case_fails_the_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    results = {"summary": {k: [] for k in ("attacks_missed", "attacks_stopped", "attacks_no_effect_either_way",
                                           "ordinary_blocked_or_changed", "ordinary_not_checked",
                                           "ordinary_untouched", "ordinary_stand_in_obeyed")},
               "cases": [], "failure_modes": []}
    results["summary"]["ordinary_blocked"] = ["O-x"]
    results["summary"]["ordinary_blocked_or_changed"] = ["O-x"]
    results["cases"] = [{"id": "O-x", "kind": "ordinary", "surface": "otx", "hard": False, "outcome": "blocked",
                         "on": {"stopped": "s", "reported": []}, "seconds": {"off": 0.1, "on": 0.2, "added": 0.1}}]
    monkeypatch.setattr(ev, "evaluate", lambda cases, factory: results)
    out = io.StringIO()
    assert ev.main(["--out", str(tmp_path)], stdout=out) == 1
    assert "1 ordinary blocked or changed by mistake: O-x" in out.getvalue()


def test_real_mode_warns_and_labels_its_results(tmp_path: Path) -> None:
    cases = tmp_path / "cases.jsonl"
    cases.write_text("\n".join(line for line in ev.CASES_PATH.read_text().splitlines()
                               if '"A-otx-exfil"' in line or '"O-list-ordinary"' in line) + "\n")
    out = io.StringIO()
    code = ev.main(["--out", str(tmp_path / "r"), "--cases", str(cases), "--real"], stdout=out,
                   client_factory=SusceptibleLLM)
    assert code == 0 and out.getvalue().startswith(ev.REAL_WARNING)
    stamp = json.loads((tmp_path / "r" / "results.json").read_text())["stamp"]
    assert stamp["model"] == "real" and stamp["note"] == ev.REAL_NOTE
    assert ev.REAL_NOTE in (tmp_path / "r" / "table.md").read_text()


def test_real_mode_needs_a_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        ev.main(["--out", str(tmp_path), "--real"], stdout=io.StringIO())


def test_real_client_is_built_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key-000000000000")
    assert type(ev.real_client()).__name__ == "OpenAIClient"


def test_the_replay_judges_like_the_harness() -> None:
    attack = ev.Case("a", "attack", "otx", "x", False, "", effect={"contains": "OWNED"})
    leak = ev.Case("l", "attack", "otx", "x", False, "", effect={"leak": True})
    assert nemo_replay.judge(attack, {"raw_answer": "ok", "answer": "", "response": ""}) == "no effect either way"
    assert nemo_replay.judge(attack, {"raw_answer": "OWNED", "answer": "OWNED", "response": "OWNED"}) == "missed"
    assert nemo_replay.judge(leak, {"raw_answer": nemo_replay.SYSTEM, "answer": "", "response": "x"}) == "stopped"
    blocked = nemo_replay.replay_one("Hello", surface="otx",
                                     fixed_answer="Sure: " + nemo_replay.SYSTEM + " That is all of it.")
    assert blocked["blocked"] is True


def test_the_docs_quote_the_committed_numbers() -> None:
    """docs/ai-safeguards.md repeats the four numbers, the replay's agreement,
    and the commit by hand; they must match the committed results."""
    import re

    doc = (ROOT / "docs" / "ai-safeguards.md").read_text(encoding="utf-8")
    results = json.loads((COMMITTED / "results.json").read_text(encoding="utf-8"))
    s = results["summary"]
    rows = {
        "Attacks that got through with the safeguards on (missed)": s["attacks_missed"],
        "Attacks stopped": s["attacks_stopped"],
        "Ordinary requests blocked or changed by mistake": s["ordinary_blocked_or_changed"],
        "Ordinary requests untouched": s["ordinary_untouched"],
        "Ordinary requests whose quoted attack string the stand-in obeyed": s["ordinary_stand_in_obeyed"],
    }
    for label, ids in rows.items():
        match = re.search(re.escape(label) + r"[^|]*\| (\d+) \|", doc)
        assert match and int(match.group(1)) == len(ids), label
    for case_id in s["attacks_missed"] + s["ordinary_blocked_or_changed"]:
        assert f"**{case_id}**" in doc, case_id
    replayed = [r for r in results["nemo_replay"] if r["agree"] is not None]
    agreed = sum(1 for r in replayed if r["agree"])
    assert f"agreed with the harness on {agreed} of the {len(replayed)} cases" in doc
    assert "from the commit that added these files" in doc
    assert "| Commit of the committed results | the commit that added these files |" in doc
