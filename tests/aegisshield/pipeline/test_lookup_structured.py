"""The NVD and OTX lookups return structured data.

``lookup_nvd`` and ``lookup_otx`` return what came back (how many, and each
kept item); ``nvd_text`` and ``otx_text`` build the prompt text from it.
Looking up and then formatting (``lookup_nvd`` + ``nvd_text``, ``lookup_otx`` +
``otx_text``) must return the same bytes as the reference formatters below,
which build the prompt text straight from the upstream objects in one pass,
fed the same fake upstream objects.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from aegisshield.core.errors import IntelLookupError
from aegisshield.pipeline import nvd_service, otx_service
from aegisshield.pipeline.nvd_service import NvdSearchConfig


def _search_nvd(api_key, cpe_prefix, version, tech, category, config):  # noqa: ANN001, ANN202
    """``lookup_nvd`` then ``nvd_text``, as the threat-model run composes them."""
    lookup = nvd_service.lookup_nvd(api_key, cpe_prefix, version, config)
    return nvd_service.nvd_text(lookup, tech=tech, category=category, version=version)


def _fetch_otx_data(api_key, industry, days, max_results, max_retries, base_delay_seconds, *,  # noqa: ANN001, ANN202
                    offline=False):
    """``lookup_otx`` then ``otx_text``, as the threat-model run composes them."""
    lookup = otx_service.lookup_otx(api_key, industry, days, max_results, max_retries,
                                    base_delay_seconds, offline=offline)
    return otx_service.otx_text(lookup, industry)

# -- reference formatters -------------------------------------------------


def _reference_nvd_text(cve_results: Any, tech: str, category: str, version: str, top_n: int) -> str:
    if not cve_results:
        return "No vulnerabilities found"

    sorted_results = sorted(
        cve_results,
        key=lambda x: (getattr(x, "score", 0) or 0, getattr(x, "published", "")),
        reverse=True,
    )[:top_n]

    entries: list[str] = []
    for idx, item in enumerate(sorted_results, start=1):
        description = "No description available"
        descriptions = getattr(item, "descriptions", None)
        if descriptions:
            try:
                description = descriptions[0].value
            except Exception:
                description = "No description available"

        published = getattr(item, "published", "")
        if published and "T" in published:
            published = published.split("T", 1)[0]

        score = getattr(item, "score", "N/A")
        entries.append(
            f"""{tech} NVD {idx}
CVE ID: {getattr(item, 'id', 'N/A')}
Technology: {tech}
Category: {category}
Version: {version}
CVSS Score: {score}
Published Date: {published or 'Unknown date'}
Description: {str(description).replace(chr(10), ' ').replace('/', '-')}|"""
        )

    result = "".join(entries)
    result += f"\n\nTotal vulnerabilities found: {len(entries)}"
    return result


def _reference_otx_text(pulses: dict, industry: str, modified_since: str, max_results: int) -> str:
    filtered_pulses = [
        pulse
        for pulse in pulses.get("results", [])
        if pulse.get("modified", "") >= modified_since and pulse.get("public", 1) == 1
    ]

    sorted_pulses = sorted(
        filtered_pulses,
        key=lambda x: x.get("modified", ""),
        reverse=True,
    )[:max_results]

    cti_blocks: list[str] = []
    for idx, pulse in enumerate(sorted_pulses, start=1):
        name = pulse.get("name", "N/A")
        description = pulse.get("description") or "No description available"
        modified = pulse.get("modified", "N/A")
        tlp = pulse.get("TLP", "N/A")
        adversary = pulse.get("adversary") or "N/A"
        families = ", ".join(pulse.get("malware_families", [])) or "N/A"

        block = (
            f"### Pulse {idx}: {name}\n\n"
            f"- **Industry**: {industry or 'N/A'}\n"
            f"- **Modified**: {modified}\n"
            f"- **TLP**: {tlp}\n"
            f"- **Adversary**: {adversary}\n"
            f"- **Malware Families**: {families}\n\n"
            f"**Description**\n\n{description}"
        )
        cti_blocks.append(block)

    if not cti_blocks:
        return "No threat intelligence data found"

    body = "\n\n---\n\n".join(cti_blocks)
    return body + f"\n\n*Total pulses found: {len(cti_blocks)}*\n"


# -- fake upstream objects -------------------------------------------------


def _cve(cve_id: Any, score: Any, published: Any, description: Any = None, **extra: Any) -> SimpleNamespace:
    fields: dict[str, Any] = {"id": cve_id, "score": score, "published": published, **extra}
    if description is not None:
        fields["descriptions"] = [SimpleNamespace(value=description)]
    return SimpleNamespace(**fields)


class _NoValue:
    """A description entry with no ``value``: the text falls back."""


def _many(n: int) -> list[SimpleNamespace]:
    return [
        _cve(f"CVE-2024-{1000 + i}", ["V31", round((i * 0.37) % 10, 1), "HIGH"], f"2024-0{1 + i % 9}-1{i % 10}T10:00:00.000")
        for i in range(n)
    ]


NVD_CASES: dict[str, list[Any]] = {
    "list-shaped scores, more than kept": _many(50),
    "two results": [
        _cve("CVE-2023-44487", ["V31", 7.5, "HIGH"], "2023-10-10T14:15:10.177", "HTTP/2 rapid reset\ncan cause DoS"),
        _cve("CVE-2025-23419", ["V31", 5.3, "MEDIUM"], "2025-02-05T18:15:31.090", "TLS session/resumption issue"),
    ],
    "missing description and score": [
        SimpleNamespace(id="CVE-2020-0001", published="2020-01-01T00:00:00"),
        SimpleNamespace(id="CVE-2020-0002", published="2020-01-02", descriptions=[]),
        SimpleNamespace(id="CVE-2020-0003", published="", descriptions=[_NoValue()]),
    ],
    "no published date, no id": [SimpleNamespace(score=["V31", 9.8, "CRITICAL"])],
}


def _fake_nvdlib(cves: Any, *, cpe_found: bool = True) -> SimpleNamespace:
    def search_cpe(**_kw: Any) -> list[Any]:
        return [SimpleNamespace(cpeName="cpe:2.3:a:vendor:product:1.0:*", deprecated=False)] if cpe_found else []

    return SimpleNamespace(searchCPE=search_cpe, searchCVE=lambda **_kw: cves)


_CONFIG = NvdSearchConfig(max_retries=1, base_delay_seconds=0.0, top_n=10)


@pytest.mark.parametrize("name", list(NVD_CASES))
def test_search_nvd_returns_the_reference_bytes(monkeypatch, name: str) -> None:
    cves = NVD_CASES[name]
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    new = _search_nvd("key", "cpe:2.3:a:vendor:product:", "1.0", "PostgreSQL", "Web application", _CONFIG)
    assert new == _reference_nvd_text(cves, "PostgreSQL", "Web application", "1.0", 10)


@pytest.mark.parametrize("cves", [[], None])
def test_search_nvd_empty_result_keeps_the_sentinel(monkeypatch, cves: Any) -> None:
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    assert _search_nvd("key", "cpe:", "1.0", "nginx", "Web", _CONFIG) == "No vulnerabilities found"
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert lookup.returned == 0 and lookup.items == []


def test_lookup_nvd_counts_what_nvd_returned_and_keeps_the_top_ten(monkeypatch) -> None:
    cves = NVD_CASES["list-shaped scores, more than kept"]
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "15.4", _CONFIG)
    assert lookup.returned == 50
    assert len(lookup.items) == 10
    # the score is kept as given, list and all
    assert isinstance(lookup.items[0].score, list) and lookup.items[0].score[0] == "V31"
    # in the same order the prompt text lists them
    text = nvd_service.nvd_text(lookup, tech="PostgreSQL", category="Web", version="15.4")
    ids_in_text = [line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("CVE ID: ")]
    assert ids_in_text == [item.id for item in lookup.items]
    assert lookup.items[0].published == lookup.items[0].published.split("T")[0]


def test_lookup_nvd_description_fallbacks(monkeypatch) -> None:
    cves = NVD_CASES["missing description and score"]
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves[1:]))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert [i.description for i in lookup.items] == ["No description available"] * 2


def _ids(monkeypatch, cves: list[Any]) -> list[Any]:
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    return [item.id for item in nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG).items]


def test_an_unscored_entry_among_scored_ones_sorts_last_and_the_lookup_succeeds(monkeypatch) -> None:
    """An entry with no score sorts after the scored ones and still counts,
    so one unscored entry never loses the whole technology."""
    cves = [SimpleNamespace(id="CVE-2020-0001", published="2020"), *NVD_CASES["two results"]]
    assert _ids(monkeypatch, cves) == ["CVE-2023-44487", "CVE-2025-23419", "CVE-2020-0001"]
    none_inside = [_cve("CVE-2024-0001", [None, None, None], "2024-05-01"), *NVD_CASES["two results"]]
    assert _ids(monkeypatch, none_inside) == ["CVE-2023-44487", "CVE-2025-23419", "CVE-2024-0001"]


def test_mixed_cvss_versions_keep_the_ten_highest_numbers(monkeypatch) -> None:
    """The score decides the order, not the CVSS version label."""
    cves = (
        [_cve(f"CVE-2010-{1000 + i}", ["V2", 10.0, "HIGH"], f"2010-01-0{1 + i}") for i in range(6)]
        + [_cve(f"CVE-2016-{1000 + i}", ["V30", 9.8, "CRITICAL"], f"2016-01-0{1 + i}") for i in range(6)]
        + [_cve(f"CVE-2024-{1000 + i}", ["V31", 2.0 + i / 10, "LOW"], f"2024-01-0{1 + i % 9}") for i in range(10)]
    )
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert lookup.returned == 22
    numbers = [item.score[1] for item in lookup.items]
    assert numbers == [10.0] * 6 + [9.8] * 4
    # equal numbers: newest published first
    assert [item.id for item in lookup.items[:6]] == [f"CVE-2010-{1000 + i}" for i in range(5, -1, -1)]
    # the entry text keeps its format, the score printed as given
    text = nvd_service.nvd_text(lookup, tech="PostgreSQL", category="Web", version="1.0")
    assert "CVSS Score: ['V2', 10.0, 'HIGH']" in text and "V31" not in text


def _v40_metrics(base_score: Any, severity: Any = "CRITICAL") -> SimpleNamespace:
    return SimpleNamespace(cvssMetricV40=[SimpleNamespace(cvssData=SimpleNamespace(baseScore=base_score, baseSeverity=severity))])


def test_an_entry_scored_only_under_cvss_4_is_ranked_by_that_score(monkeypatch) -> None:
    """nvdlib sets ``score`` to ``[None, None, None]`` for an entry that has
    only a CVSS 4.0 score. It must rank by its 4.0 number, not last, or "the
    10 highest-scored" would be untrue for it."""
    cves = [_cve(f"CVE-2024-{1000 + i}", ["V31", 5.0 + i / 10, "MEDIUM"], f"2024-01-{10 + i}") for i in range(12)]
    cves.append(_cve("CVE-2025-4040", [None, None, None], "2025-02-01", metrics=_v40_metrics(9.9)))
    cves.append(_cve("CVE-2025-4041", [None, None, None], "2025-02-02", metrics=_v40_metrics("high")))  # not a number
    cves.append(_cve("CVE-2025-4042", [None, None, None], "2025-02-03"))  # no score of any kind
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert lookup.returned == 15
    assert lookup.items[0].id == "CVE-2025-4040"
    assert lookup.items[0].score == ["V40", 9.9, "CRITICAL"]
    kept = [item.id for item in lookup.items]
    assert "CVE-2025-4041" not in kept and "CVE-2025-4042" not in kept
    text = nvd_service.nvd_text(lookup, tech="PostgreSQL", category="Web", version="1.0")
    assert "CVSS Score: ['V40', 9.9, 'CRITICAL']" in text


def test_a_3x_score_is_used_as_given_even_when_a_4_score_exists(monkeypatch) -> None:
    """An entry nvdlib already scored keeps that score: nothing changes for it."""
    cves = [_cve("CVE-2024-2000", ["V31", 7.5, "HIGH"], "2024-03-01", metrics=_v40_metrics(9.9))]
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert lookup.items[0].score == ["V31", 7.5, "HIGH"]


class _Unprintable:
    """A score object that is not a number of any kind."""


@pytest.mark.parametrize(
    "score",
    [
        ["V31", 10**400, "HIGH"],
        ("V31", 7.5, "HIGH"),
        7.5,
        10**400,
        None,
        [None, None, None],
        [],
        ["V31", float("nan"), "X"],
        ["V31", True, "X"],
        ["V31", "9.8", "X"],
        float("inf"),
        "9.8",
        _Unprintable(),
        {"score": 9.8},
    ],
    ids=lambda v: type(v).__name__,
)
def test_no_score_shape_makes_the_sort_raise(monkeypatch, score: Any) -> None:
    cves = [*NVD_CASES["two results"], _cve("CVE-2024-0001", score, "2024-05-01"), SimpleNamespace(id="CVE-2024-0002")]
    ids = _ids(monkeypatch, cves)
    assert sorted(ids) == sorted(["CVE-2023-44487", "CVE-2025-23419", "CVE-2024-0001", "CVE-2024-0002"])
    # no score attribute: no number, and no date to break the tie, so last
    assert ids[-1] == "CVE-2024-0002"


def test_odd_published_values_do_not_raise(monkeypatch) -> None:
    cves = [
        _cve("CVE-2024-0001", ["V31", 5.0, "X"], None),
        _cve("CVE-2024-0002", ["V31", 5.0, "X"], ["2025"]),
        _cve("CVE-2024-0003", ["V31", 5.0, "X"], "2024-01-01"),
    ]
    assert _ids(monkeypatch, cves)[0] == "CVE-2024-0003"


@pytest.mark.parametrize(
    "scores",
    [
        [["V31", 7.5, "HIGH"], ["V31", 9.8, "CRITICAL"], ["V31", 7.5, "HIGH"], ["V31", 1.0, "LOW"]],
        [["V2", 5.0, "MEDIUM"], ["V2", 4.3, "MEDIUM"], ["V2", 10.0, "HIGH"]],
        [7.5, 9.8, 7.5, 0.0, 3.1],
    ],
)
def test_same_label_scores_give_the_reference_bytes(monkeypatch, scores: list[Any]) -> None:
    cves = [_cve(f"CVE-2024-{1000 + i}", s, f"2024-0{1 + i % 3}-0{1 + i % 2}") for i, s in enumerate(scores)]
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves))
    new = _search_nvd("key", "cpe:", "1.0", "PostgreSQL", "Web", _CONFIG)
    assert new == _reference_nvd_text(cves, "PostgreSQL", "Web", "1.0", 10)


def test_the_cve_search_asks_for_one_page_and_marks_a_full_one(monkeypatch) -> None:
    asked: list[dict] = []
    cves = _many(nvd_service.MAX_NVD_RESULTS)
    monkeypatch.setattr(nvd_service, "nvdlib", SimpleNamespace(
        searchCPE=_fake_nvdlib([]).searchCPE, searchCVE=lambda **kw: asked.append(kw) or cves))
    lookup = nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)
    assert asked[0]["limit"] == nvd_service.MAX_NVD_RESULTS
    assert lookup.truncated is True and lookup.returned == nvd_service.MAX_NVD_RESULTS
    text = nvd_service.nvd_text(lookup, tech="x", category="y", version="1.0")
    assert text.endswith(f"NVD lists more than {nvd_service.MAX_NVD_RESULTS:,} CVEs for this version; "
                         f"these were chosen from the first {nvd_service.MAX_NVD_RESULTS:,} it returned.")
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(cves[:3]))
    assert nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG).truncated is False


def test_search_nvd_raises_on_upstream_failure(monkeypatch) -> None:
    def boom(**_kw: Any) -> list[Any]:
        raise RuntimeError("socket closed for apiKey=sk-123")

    monkeypatch.setattr(
        nvd_service, "nvdlib", SimpleNamespace(searchCPE=_fake_nvdlib([]).searchCPE, searchCVE=boom)
    )
    with pytest.raises(IntelLookupError):
        _search_nvd("key", "cpe:", "1.0", "x", "y", _CONFIG)
    with pytest.raises(IntelLookupError):
        nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)


def test_search_nvd_raises_when_no_cpe_matches(monkeypatch) -> None:
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib([], cpe_found=False))
    # the message is a fixed sentence; it does not quote the CPE prefix
    with pytest.raises(IntelLookupError, match="NVD has no entry for this product and version"):
        nvd_service.lookup_nvd("key", "cpe:", "1.0", _CONFIG)


def test_search_nvd_logs_the_technology_and_version(monkeypatch, caplog) -> None:
    monkeypatch.setattr(nvd_service, "nvdlib", _fake_nvdlib(NVD_CASES["two results"]))
    with caplog.at_level(logging.INFO, logger="aegisshield.pipeline.nvd_service"):
        _search_nvd("key", "cpe:", "1.24.0", "nginx", "Web", _CONFIG)
    assert "NVD results generated for nginx (1.24.0)" in caplog.text


# -- OTX -------------------------------------------------------------------


def _pulse(name: str, modified: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "modified": modified, **extra}


OTX_CASES: dict[str, dict[str, Any]] = {
    "mixed": {
        "results": [
            _pulse("Old report", "2001-01-01T00:00:00"),
            _pulse("Private", "2025-01-01T00:00:00", public=0),
            _pulse(
                "Hive Attacks: Analysis",
                "2025-03-02T10:11:12.000",
                description="Ransomware\ntargeting retailers",
                TLP="white",
                adversary="Hive",
                malware_families=["Hive", "BlackCat"],
            ),
            _pulse("No fields", "2025-03-01T00:00:00", description="", adversary=None, malware_families=[]),
            *[_pulse(f"Report {i}", f"2024-0{1 + i % 9}-01T00:00:00", public=1) for i in range(12)],
        ]
    },
    "no name, no modified": {"results": [{"public": 1}]},
}


class _FakeOtx:
    pulses: Any = None

    def __init__(self, _key: str) -> None:
        pass

    def search_pulses(self, _query: str, max_results: int = 0) -> Any:
        return type(self).pulses


class _FrozenNow:
    """``datetime`` with a fixed ``now`` so the window is the same in both copies."""

    @staticmethod
    def now() -> Any:
        from datetime import datetime

        return datetime(2026, 11, 13, 12, 0, 0)


def _otx_setup(monkeypatch, pulses: Any) -> None:
    fake = type("FakeOtx", (_FakeOtx,), {"pulses": pulses})
    monkeypatch.setattr(otx_service, "BoundedOTXv2", fake)
    monkeypatch.setattr(otx_service, "datetime", _FrozenNow)


def _since(days: int) -> str:
    from datetime import timedelta

    return (_FrozenNow.now() - timedelta(days=days)).isoformat()


@pytest.mark.parametrize("name", list(OTX_CASES))
def test_fetch_otx_data_returns_the_reference_bytes(monkeypatch, name: str) -> None:
    pulses = OTX_CASES[name]
    _otx_setup(monkeypatch, pulses)
    new = _fetch_otx_data("key", "Retail", 2920, 10, 1, 0.0)
    assert new == _reference_otx_text(pulses, "Retail", _since(2920), 10)


def test_fetch_otx_data_none_found_keeps_the_sentinel(monkeypatch) -> None:
    pulses = {"results": [_pulse("Old", "1999-01-01T00:00:00")]}
    _otx_setup(monkeypatch, pulses)
    assert _fetch_otx_data("key", "Retail", 30, 10, 1, 0.0) == "No threat intelligence data found"
    lookup = otx_service.lookup_otx("key", "Retail", 30, 10, 1, 0.0)
    assert (lookup.state, lookup.returned, lookup.pulses) == ("none", 0, [])


def test_lookup_otx_counts_what_passed_the_filter_and_keeps_the_newest(monkeypatch) -> None:
    pulses = OTX_CASES["mixed"]
    _otx_setup(monkeypatch, pulses)
    lookup = otx_service.lookup_otx("key", "Retail", 2920, 10, 1, 0.0)
    # 14 are public and in the window (one too old, one private)
    assert lookup.state == "found" and lookup.returned == 14 and len(lookup.pulses) == 10
    assert lookup.pulses[0]["name"] == "Hive Attacks: Analysis"
    assert otx_service.otx_text(lookup, "Retail") == _reference_otx_text(pulses, "Retail", _since(2920), 10)


def test_lookup_otx_offline_is_off_and_keeps_the_sentinel(monkeypatch) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("OTXv2 client constructed in offline mode")

    monkeypatch.setattr(otx_service, "BoundedOTXv2", boom)
    # ``offline`` is the switch that turns OTX off
    lookup = otx_service.lookup_otx("key", "Retail", 30, 10, 1, 0.0, offline=True)
    assert (lookup.state, lookup.returned, lookup.pulses) == ("off", 0, [])
    assert otx_service.otx_text(lookup, "Retail") == "OTX threat intelligence disabled (offline mode)"
    assert _fetch_otx_data("key", "Retail", 30, 10, 1, 0.0, offline=True) == (
        "OTX threat intelligence disabled (offline mode)"
    )


def test_lookup_otx_raises_when_otx_does_not_answer(monkeypatch) -> None:
    _otx_setup(monkeypatch, {})
    with pytest.raises(IntelLookupError):
        otx_service.lookup_otx("key", "Retail", 30, 10, 1, 0.0)
    with pytest.raises(IntelLookupError):
        _fetch_otx_data("key", "Retail", 30, 10, 1, 0.0)
