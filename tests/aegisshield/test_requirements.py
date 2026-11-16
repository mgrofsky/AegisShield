"""Every requirement is pinned to one exact version, and that version is
what the test environment has installed."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

from packaging.requirements import Requirement

REQUIREMENTS = Path(__file__).resolve().parents[2] / "requirements.txt"


def _requirements() -> dict[str, Requirement]:
    lines = REQUIREMENTS.read_text(encoding="utf-8").splitlines()
    reqs = [Requirement(line) for line in lines if line.strip() and not line.lstrip().startswith("#")]
    return {r.name.lower(): r for r in reqs}


DEV_REQUIREMENTS = REQUIREMENTS.with_name("requirements-dev.txt")


def test_every_requirement_is_pinned_to_the_installed_version() -> None:
    for path in (REQUIREMENTS, DEV_REQUIREMENTS):
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            req = Requirement(line)
            assert [s.operator for s in req.specifier] == ["=="], (path.name, req.name)
            assert importlib.metadata.version(req.name) in req.specifier, (path.name, req.name)


def test_the_pdf_escaping_and_safeguard_libraries_are_in_the_runtime_requirements() -> None:
    reqs = _requirements()
    for name in ("xhtml2pdf", "markdown2", "nemoguardrails"):
        assert name in reqs, name
    assert str(reqs["nemoguardrails"].specifier) == "==0.24.1"


def test_provider_sdks_are_pinned_to_the_installed_versions() -> None:
    """The three provider SDKs are pinned exactly, to what the backends
    were written and tested against, and that is what is installed."""
    reqs = _requirements()
    for name in ("anthropic", "boto3", "google-genai"):
        spec = reqs[name].specifier
        assert [s.operator for s in spec] == ["=="], name
        assert importlib.metadata.version(name) in spec, name


def test_each_provider_sdk_has_a_comment_line() -> None:
    lines = REQUIREMENTS.read_text(encoding="utf-8").splitlines()
    for name in ("anthropic", "boto3", "google-genai"):
        index = next(i for i, line in enumerate(lines) if line.startswith(f"{name}=="))
        assert lines[index - 1].startswith("# "), name
