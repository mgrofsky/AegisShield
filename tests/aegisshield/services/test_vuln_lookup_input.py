"""Versions and pasted input for the lookup."""

from __future__ import annotations

import pytest

from aegisshield.services import vuln_lookup
from aegisshield.services.vuln_lookup import DetectedTech

_VERSION_TABLE = [
        ("2.4.69", "2.4.69", False),
        ("2.4.69 (Debian)", "2.4.69", True),
        ("2.4.41 (Ubuntu)", "2.4.41", True),
        ("2.4.6 (Red Hat Enterprise Linux)", "2.4.6", True),
        ("2.4.6 (CentOS)", "2.4.6", True),
        ("2.4.58 (Win64)", "2.4.58", False),
        ("1.18.0-0ubuntu1", "1.18.0", True),
        ("1.2.3+deb12u1", "1.2.3", True),
        ("1.20.1-1.el8", "1.20.1", True),
        ("8.2.35", "8.2.35", False),
        ("1.1.1w", "1.1.1w", False),
        ("6.5.0-beta1", None, False),
        ("1.0.0rc1", None, False),
        ("6.4.2~beta1", None, False),
        ("6.4.2 beta1", None, False),
        ("10.0.0-M1", None, False),
        ("10.0.0M1", None, False),
        ("1.2.3-0.rc1.el9", None, False),
        ("1.2.3_alpha2", None, False),
        ("1.2.3.dev0", None, False),
        ("1.2.3-SNAPSHOT", None, False),
        ("1.2.3-preview.1", None, False),
        ("6.4.2 (beta1)", None, False),
        ("6.4.2 [rc1]", None, False),
        ("6.4.2 (beta)", None, False),
        ("1.0.1-4ubuntu5.precise", "1.0.1", True),
        ("1.2.3_build7", None, False),
]


@pytest.mark.parametrize(("raw", "lookup", "distro"), _VERSION_TABLE)
def test_parse_version(raw, lookup, distro) -> None:
    info = vuln_lookup.parse_version(raw)
    assert info is not None
    assert (info.display, info.lookup, info.distro_build) == (raw, lookup, distro)
    assert vuln_lookup.parse_version("v" + raw).display == raw


@pytest.mark.parametrize("raw", ["", "abc", "(hidden)", None, "x1.0", "1.0\x002", "1" * 65, 3])
def test_not_a_version(raw) -> None:
    assert vuln_lookup.parse_version(raw) is None


def test_version_parts() -> None:
    assert vuln_lookup.version_parts("8.2") == 2
    assert vuln_lookup.version_parts("1.2.3-beta") == 3
    assert vuln_lookup.version_parts("beta") == 0


def test_parse_tech_list() -> None:
    raw = (
        "# comment\n"
        "nginx 1.18.0\n"
        "\n"
        "Apache HTTP Server v2.4.69 (Debian)\n"
        "OpenSSL 1.1.1-rc1\n"
        "Microsoft IIS\n"
        "PHP 7.4.3-1+deb11u5\n"
    )
    assert [(t.name, t.version, t.source) for t in vuln_lookup.parse_tech_list(raw)] == [
        ("nginx", "1.18.0", "tech_list"),
        ("Apache HTTP Server", "2.4.69 (Debian)", "tech_list"),
        ("OpenSSL", "1.1.1-rc1", "tech_list"),
        # The whole name is kept; the first word alone ("Microsoft") maps to nothing.
        ("Microsoft IIS", None, "tech_list"),
        ("PHP", "7.4.3-1+deb11u5", "tech_list"),
    ]
    assert vuln_lookup.parse_tech_list("") == []


@pytest.mark.parametrize("raw", [row[0] for row in _VERSION_TABLE])
def test_a_pasted_line_carries_every_version_parse_version_reads(raw) -> None:
    """The line pattern must read ``1.1.1w``, Debian builds, and spaced
    pre-releases, or the version is folded into the name."""
    (tech,) = vuln_lookup.parse_tech_list(f"nginx {raw}")
    assert (tech.name, tech.version) == ("nginx", raw)
    (prefixed,) = vuln_lookup.parse_tech_list(f"Apache HTTP Server v{raw}")
    assert (prefixed.name, prefixed.version) == ("Apache HTTP Server", raw)


@pytest.mark.parametrize(
    ("line", "name", "version"),
    [
        # A digit-led tail that is not a release stays the version, so the
        # result says the version is not recognized; the name stays clean.
        ("Acme 1.2.3x9!", "Acme", "1.2.3x9!"),
        ("Python 3 thing", "Python", "3 thing"),
        # No version: a name that starts with a digit, or a tail with a control character.
        ("7zip 1.2.3", "7zip 1.2.3", None),
        ("nginx 1.0\x002", "nginx 1.0\x002", None),
        ("nginx stable", "nginx stable", None),
    ],
)
def test_how_a_line_splits(line, name, version) -> None:
    (tech,) = vuln_lookup.parse_tech_list(line)
    assert (tech.name, tech.version) == (name, version)


def test_an_unversioned_multi_word_name_still_maps() -> None:
    from aegisshield.services.tech_products import product_for

    (tech,) = vuln_lookup.parse_tech_list("Microsoft IIS")
    assert product_for(tech.name).name == "Microsoft IIS"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ([{"name": "nginx", "version": "1.18.0"}, {"product": "PHP", "ver": 8}], [("nginx", "1.18.0"), ("PHP", "8")]),
        ({"technologies": [{"name": "nginx"}]}, [("nginx", None)]),
        ({"stack": [{"name": "Redis", "version": "7.2.4"}, "junk", {"name": ""}]}, [("Redis", "7.2.4")]),
        ({"name": "nginx", "version": "1.18.0"}, [("nginx", "1.18.0")]),
        ({"nginx": "1.18.0", "PHP": None}, [("nginx", "1.18.0"), ("PHP", None)]),
        ("not json", []),
        (None, []),
    ],
)
def test_parse_json_input(payload, expected) -> None:
    out = vuln_lookup.parse_json_input(payload)
    assert [(t.name, t.version) for t in out] == expected
    assert all(t.source == "json" for t in out)


def test_parse_text_finds_banners_once() -> None:
    text = "Server: nginx/1.18.0 then HTTP/1.1 and nginx/1.18.0 again, OpenSSH/8.9"
    assert [(t.name, t.version) for t in vuln_lookup.parse_text(text)] == [
        ("nginx", "1.18.0"),
        ("OpenSSH", "8.9"),
    ]
    assert vuln_lookup.parse_text("") == []


def test_detected_tech_key_ignores_case_and_a_missing_version() -> None:
    assert DetectedTech("A", None, "x", "A").key() == "a|"
    assert DetectedTech("NGINX", "1.18.0", "x", "n").key() == DetectedTech("nginx", "1.18.0", "y", "n").key()
