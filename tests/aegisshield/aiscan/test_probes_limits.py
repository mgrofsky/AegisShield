"""The probe list and the limits: fixed in code, checked before anything runs."""

from __future__ import annotations

import pytest

from aegisshield.aiscan import limits, probes
from aegisshield.aiscan.limits import ScanLimits, check_budget, check_seed, planned_requests
from aegisshield.config import DEFAULT_JOB_TIMEOUT_SECONDS
from aegisshield.core.errors import ValidationError


def test_probe_ids_are_unique_and_shaped_like_module_class():
    ids = [p.id for p in probes.PROBES]
    assert len(ids) == len(set(ids))
    for pid in ids:
        module, _, cls = pid.partition(".")
        assert module.isidentifier() and cls.isidentifier()


def test_default_probes_are_the_four_verified_ones_and_on_the_list():
    assert probes.DEFAULT_PROBE_IDS == (
        "promptinject.HijackHateHumans",
        "latentinjection.LatentInjectionReport",
        "web_injection.MarkdownImageExfil",
        "encoding.InjectBase64",
    )
    assert probes.check_probe_ids(probes.DEFAULT_PROBE_IDS) == probes.DEFAULT_PROBE_IDS


@pytest.mark.parametrize("excluded", [
    "sysprompt_extraction.SystemPromptExtraction",
    "latentinjection.LatentJailbreak",
    "latentinjection.LatentWhois",
])
def test_probes_that_need_a_download_or_ignore_the_cap_are_not_offered(excluded):
    with pytest.raises(ValidationError):
        probes.check_probe_ids([excluded])


@pytest.mark.parametrize("bad", [
    ["promptinject.HijackHateHumans", "promptinject.Nope"],
    ["promptinject.HijackHateHumans; rm -rf /"],
    ["probes.promptinject.HijackHateHumans"],
    [" promptinject.HijackHateHumans"],
    [None],
    [3],
    ["promptinject.HijackHateHumans,dan.DanInTheWild"],
])
def test_any_id_not_on_the_list_is_refused(bad):
    with pytest.raises(ValidationError, match="not on the list"):
        probes.check_probe_ids(bad)


def test_empty_selection_is_refused():
    with pytest.raises(ValidationError, match="at least one"):
        probes.check_probe_ids([])


def test_selection_is_deduplicated_and_put_in_list_order():
    got = probes.check_probe_ids(["encoding.InjectBase64", "promptinject.HijackHateHumans",
                                  "encoding.InjectBase64"])
    assert got == ("promptinject.HijackHateHumans", "encoding.InjectBase64")


def test_fixed_prompt_probes_count_their_fixed_number():
    assert probes.probe("web_injection.MarkdownImageExfil").prompts(2) == 12
    assert probes.probe("promptinject.HijackHateHumans").prompts(2) == 2


def test_limits_defaults_and_ranges():
    default = ScanLimits.build()
    assert default == ScanLimits()
    for limit in (limits.GENERATIONS, limits.PROMPTS_PER_PROBE, limits.TOTAL_REQUESTS,
                  limits.REQUEST_TIMEOUT_SECONDS, limits.WALL_CLOCK_SECONDS):
        assert limit.minimum <= limit.default <= limit.maximum
    # A scan always stops itself before the job runner's default timeout.
    assert limits.WALL_CLOCK_SECONDS.maximum < DEFAULT_JOB_TIMEOUT_SECONDS


@pytest.mark.parametrize("field,value", [
    ("generations", 4), ("generations", 0), ("prompts_per_probe", 21), ("total_requests", 301),
    ("request_timeout_seconds", 9), ("wall_clock_seconds", 1501), ("generations", True),
    ("generations", 1.5), ("generations", "2"),
])
def test_values_past_a_hard_maximum_or_not_whole_numbers_are_refused(field, value):
    with pytest.raises(ValidationError):
        ScanLimits.build(**{field: value})


def test_budget_counts_prompts_times_generations_and_refuses_overruns():
    lim = ScanLimits.build(generations=2, prompts_per_probe=3, total_requests=30)
    ids = ["promptinject.HijackHateHumans", "web_injection.MarkdownImageExfil"]
    assert planned_requests(ids, lim) == (3 + 12) * 2
    assert check_budget(ids, lim) == 30
    with pytest.raises(ValidationError, match="need up to 36 requests"):
        check_budget([*ids, "encoding.InjectBase64"], lim)


def test_seed():
    assert check_seed(None) is None
    assert check_seed(7) == 7
    with pytest.raises(ValidationError):
        check_seed(-1)
    assert ScanLimits().to_dict()["total_requests"] == limits.TOTAL_REQUESTS.default
