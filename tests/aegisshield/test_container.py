"""The Dockerfile, CI, and Streamlit Cloud package lists hold only what the
app needs: tshark (and curl for the image's health check), no compiler or
Cairo/Pango packages, wheels only, and an app tree the app user can read
but not change."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text()


def _apt_packages(text: str) -> set[str]:
    install = re.search(r"apt-get install -y --no-install-recommends(.*?)(?:&&|\n\n|$)", text, re.S)
    assert install, "no apt-get install line"
    return {word for word in re.split(r"[\s\\]+", install.group(1)) if word}


def test_image_system_packages_are_curl_and_tshark_only() -> None:
    assert _apt_packages(DOCKERFILE) == {"curl", "tshark"}
    assert "wireshark-common/install-setuid boolean false" in DOCKERFILE


def test_image_installs_wheels_only() -> None:
    assert "pip install --no-cache-dir --only-binary=:all: -r requirements.txt" in DOCKERFILE


def test_app_tree_is_readable_and_the_app_runs_unprivileged() -> None:
    copy_app = DOCKERFILE.index("COPY . /app")
    chmod = DOCKERFILE.index("RUN chmod -R a+rX /app")
    user = DOCKERFILE.index("USER aegis")
    assert copy_app < chmod < user
    assert "--uid 10001" in DOCKERFILE
    assert "HEALTHCHECK" in DOCKERFILE and 'ENTRYPOINT ["streamlit", "run", "main.py"' in DOCKERFILE


def test_ci_and_streamlit_cloud_install_only_tshark() -> None:
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    assert _apt_packages(workflow) == {"tshark"}
    packages = (ROOT / "packages.txt").read_text().split()
    assert packages == ["tshark"]


def test_ci_workflow_asks_only_for_read_access() -> None:
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    head = workflow.split("\non:", 1)[0]
    assert "contents: read" in head and "write" not in head


def test_the_image_carries_the_rails_configuration() -> None:
    """The safeguards read their NeMo Guardrails files from the package, which
    the allowlist copies whole; nothing in it drops YAML or Colang files."""
    rails = ROOT / "aegisshield" / "safeguards" / "rails"
    assert (rails / "config.yml").is_file() and (rails / "rails.co").is_file()
    ignore = [line.strip() for line in (ROOT / ".dockerignore").read_text().splitlines()]
    assert "!aegisshield/" in ignore
    assert not any(line.endswith((".yml", ".co")) for line in ignore if not line.startswith("#"))
