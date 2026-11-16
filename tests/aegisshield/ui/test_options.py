"""The wizard's option lists: every option reaches the pipeline with the
string it expects, and nothing is chosen for the visitor."""

from __future__ import annotations

import re

import pytest

from aegisshield.pipeline import ai_system, catalog_service
from aegisshield.pipeline.pattern_detection_service import supported_patterns
from aegisshield.pipeline.schemas import AppProfile
from aegisshield.services.vuln_lookup import prefill_from_lookup
from aegisshield.ui import options

CPE = re.compile(r"^cpe:2\.3:[aoh]:[^:]+:[^:]+:$")


def _profile(**overrides: object) -> AppProfile:
    base = {"app_type": options.APP_TYPE_OPTIONS[0], "industry_sector": options.INDUSTRY_OPTIONS[0],
            "sensitive_data": options.DATA_SENSITIVITY_OPTIONS[0],
            "internet_facing": options.INTERNET_FACING_OPTIONS[0]}
    return AppProfile(**{**base, **overrides})


def test_application_types_cover_every_type_the_pipeline_routes_on() -> None:
    apps = set(options.APP_TYPE_OPTIONS)
    assert catalog_service._MOBILE_APP_TYPES <= apps
    assert catalog_service._ICS_APP_TYPES <= apps
    assert ai_system.AI_APP_TYPES <= apps


@pytest.mark.parametrize("app_type", options.APP_TYPE_OPTIONS)
def test_each_application_type_builds_a_profile_and_a_catalog_route(app_type: str) -> None:
    assert _profile(app_type=app_type).app_type == app_type
    domains, _atlas = catalog_service.domains_for_app_type(app_type)
    assert domains[0] == "enterprise"


def test_ai_types_pick_atlas_and_mobile_and_ics_types_pick_their_catalogs() -> None:
    assert catalog_service.domains_for_app_type("AI/ML Systems") == (["enterprise"], True)
    assert "mobile" in catalog_service.domains_for_app_type("Mobile application")[0]
    assert "ics" in catalog_service.domains_for_app_type("ICS or SCADA System")[0]


def test_pattern_values_are_exactly_what_detection_supports() -> None:
    assert sorted(p.value for p in options.PATTERN_OPTIONS) == supported_patterns()
    assert options.AI_PATTERNS == {p.value for p in options.PATTERN_OPTIONS}


@pytest.mark.parametrize(("field", "values"), [
    ("industry_sector", options.INDUSTRY_OPTIONS),
    ("sensitive_data", options.DATA_SENSITIVITY_OPTIONS),
    ("internet_facing", options.INTERNET_FACING_OPTIONS),
    ("num_employees", options.NUM_EMPLOYEES_OPTIONS),
    ("technical_ability", options.TECHNICAL_ABILITY_OPTIONS),
])
def test_every_single_choice_option_is_accepted(field: str, values: tuple[str, ...]) -> None:
    for value in values:
        assert getattr(_profile(**{field: value}), field) == value


def test_all_three_technical_ability_levels_are_offered() -> None:
    assert options.TECHNICAL_ABILITY_OPTIONS == ("Low", "Medium", "High")


def test_multi_choice_lists_are_accepted_whole() -> None:
    profile = _profile(compliance_requirements=list(options.COMPLIANCE_OPTIONS),
                       authentication=list(options.AUTHENTICATION_OPTIONS),
                       app_pattern=[p.value for p in options.PATTERN_OPTIONS])
    assert len(profile.compliance_requirements) == len(options.COMPLIANCE_OPTIONS)


def test_lists_have_no_duplicates() -> None:
    for values in (options.APP_TYPE_OPTIONS, options.INDUSTRY_OPTIONS, options.COMPLIANCE_OPTIONS,
                   options.AUTHENTICATION_OPTIONS):
        assert len(values) == len(set(values))


def test_merged_lists_keep_the_old_repos_entries() -> None:
    # Entries from the older step 2 lists, kept with their original spelling.
    old_apps = {"5G/Wireless System", "Cloud application", "Wearable Devices", "Web application"}
    assert old_apps <= set(options.APP_TYPE_OPTIONS)
    assert len(options.APP_TYPE_OPTIONS) == 51
    assert len(options.INDUSTRY_OPTIONS) == 31
    for renamed in ("PCI DSS v4.0", "FDA 21 CFR Part 11", "ISO 27001", "SOC 2"):
        assert renamed in options.COMPLIANCE_OPTIONS
    for renamed in ("Basic Authentication", "MFA (TOTP / Push)", "OAuth 2.0", "Single Sign-On (SSO)"):
        assert renamed in options.AUTHENTICATION_OPTIONS


def test_sectors_are_general_with_healthcare_an_ordinary_entry() -> None:
    assert "Healthcare" in options.INDUSTRY_OPTIONS
    assert {"Retail", "Financial", "Energy", "Education"} <= set(options.INDUSTRY_OPTIONS)
    assert options.DATA_SENSITIVITY_OPTIONS == ("High", "Medium", "Low", "None")


def test_every_technology_has_a_cpe_prefix_and_a_unique_key() -> None:
    choices = list(options.technology_choices())
    assert len(choices) > 150
    assert all(CPE.match(c.cpe) for c in choices)
    keys = [c.key for c in choices]
    assert len(keys) == len(set(keys))
    assert all(re.fullmatch(r"[A-Za-z0-9_]+", k) for k in keys)


def test_a_library_listed_under_two_frameworks_gets_two_keys() -> None:
    gunicorn = [c for c in options.technology_choices() if c.name == "Gunicorn"]
    assert {c.parent for c in gunicorn} == {"Django", "Flask"}
    assert len({c.key for c in gunicorn}) == 2


def test_source_cpes_win_where_the_old_catalog_differed() -> None:
    by_name = {c.name: c.cpe for c in options.technology_choices() if c.parent is None}
    assert by_name["MySQL"] == "cpe:2.3:a:oracle:mysql:"
    assert by_name["Django"] == "cpe:2.3:a:djangoproject:django:"
    assert by_name["Redis"] == "cpe:2.3:a:redis:redis:"


def test_technologies_reach_the_profile_as_name_to_cpe() -> None:
    choice = next(c for c in options.technology_choices() if c.name == "PostgreSQL")
    profile = _profile(selected_technologies={choice.name: choice.cpe},
                       selected_versions={choice.name: "15.4"})
    assert profile.selected_technologies == {"PostgreSQL": "cpe:2.3:a:postgresql:postgresql:"}


def test_the_catalog_is_in_the_shape_prefill_reads() -> None:
    lookup = {"technologies": [{"name": "PostgreSQL", "product": "postgresql:postgresql",
                                "lookup_version": "15.4.0", "state": "found"}]}
    prefill = prefill_from_lookup(lookup, options.form_catalog())
    assert prefill["selected_technologies"].get("PostgreSQL") == "cpe:2.3:a:postgresql:postgresql:"


# Version format: empty, or up to four dot-separated numbers or wildcards.
@pytest.mark.parametrize("version", ["", "  ", "1", "1.2", "1.2.3", "1.2.3.4", "1.2.*", "1.*", "*"])
def test_validate_version_accepts(version: str) -> None:
    assert options.validate_version(version) is None


def test_validate_version_rejects_five_segments() -> None:
    assert options.validate_version("1.2.3.4.5") == "Version should not have more than 4 segments."


@pytest.mark.parametrize("version", ["1.2.x", "v1.2", "1..2", "abc", "1.2-beta"])
def test_validate_version_rejects_non_numeric_segments(version: str) -> None:
    message = options.validate_version(version)
    assert message is not None and message.startswith("Version should be numbers or wildcards")


def test_example_description_is_long_enough_and_general() -> None:
    assert len(options.EXAMPLE_DESCRIPTION) >= options.MIN_DESCRIPTION_CHARS
    assert "checkout" in options.EXAMPLE_DESCRIPTION
