"""Packaged reference data (ATLAS, NIST CSF, regulations, threat cards, CPE map).

The files under ``atlas``, ``nist``, ``regulations``, ``threat_cards``, and
``tech_cpe_map.json`` are read as they are. The ATLAS file is written by
``tools/refresh_mitre.py`` (see ``atlas/SOURCE.md``). The MITRE ATT&CK
bundles are not packaged here: the repo's ``MITRE_ATTACK_DATA`` directory
holds them.
"""

from __future__ import annotations

from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _DATA_DIR.parent.parent


def data_path(*parts: str) -> Path:
    """Path to a file or directory inside the package data directory.

    Raises ``ValueError`` if the parts would point outside it.
    """
    path = _DATA_DIR.joinpath(*parts).resolve()
    if not path.is_relative_to(_DATA_DIR):
        raise ValueError("data path must stay inside the data directory")
    return path


def mitre_data_dir() -> Path:
    """The directory holding the MITRE ATT&CK STIX bundles (``*-attack.json``)."""
    return _REPO_ROOT / "MITRE_ATTACK_DATA"
