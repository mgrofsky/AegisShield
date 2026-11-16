"""Links to the public MITRE ATT&CK and MITRE ATLAS pages for an id.

The ATLAS page forms were confirmed, not guessed: the bundled ATLAS
2026.10 text links to its own pages as ``/techniques/AML.T0051``,
``/techniques/AML.T0051.000``, and ``/mitigations/AML.M0015``, and the
atlas.mitre.org application declares the routes
``/:objectTypePlural(tactics|techniques|mitigations|studies|entities|software)/:id``
and ``/studies/:id``. The site renders those pages in the browser; a client
that does not run its script (a link checker) gets an HTTP 404 status.

Each function returns None for an id of the wrong shape, so a caller links
only what it can trust. The shapes are fixed-length and anchored, so every
check is linear in the length of its input.
"""

from __future__ import annotations

import re

ATTACK_BASE = "https://attack.mitre.org/techniques/"
ATLAS_BASE = "https://atlas.mitre.org/"

_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
_ATLAS_TECHNIQUE_ID = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")
_ATLAS_MITIGATION_ID = re.compile(r"AML\.M\d{4}")
_ATLAS_CASE_STUDY_ID = re.compile(r"AML\.CS\d{4}")


def _clean(value: object) -> str:
    return str(value or "").strip()


def is_atlas_technique_id(value: object) -> bool:
    """True for an id shaped like an ATLAS technique or sub-technique."""
    return _ATLAS_TECHNIQUE_ID.fullmatch(_clean(value)) is not None


def attack_url(technique_id: object) -> str | None:
    """The attack.mitre.org page (``T1078.004`` becomes ``.../T1078/004/``)."""
    value = _clean(technique_id)
    if not _ATTACK_ID.fullmatch(value):
        return None
    return f"{ATTACK_BASE}{value.replace('.', '/')}/"


def atlas_technique_url(technique_id: object) -> str | None:
    """The atlas.mitre.org page of an ATLAS technique or sub-technique."""
    value = _clean(technique_id)
    return f"{ATLAS_BASE}techniques/{value}" if _ATLAS_TECHNIQUE_ID.fullmatch(value) else None


def atlas_mitigation_url(mitigation_id: object) -> str | None:
    """The atlas.mitre.org page of an ATLAS mitigation."""
    value = _clean(mitigation_id)
    return f"{ATLAS_BASE}mitigations/{value}" if _ATLAS_MITIGATION_ID.fullmatch(value) else None


def atlas_case_study_url(case_study_id: object) -> str | None:
    """The atlas.mitre.org page of an ATLAS case study."""
    value = _clean(case_study_id)
    return f"{ATLAS_BASE}studies/{value}" if _ATLAS_CASE_STUDY_ID.fullmatch(value) else None


def technique_url(technique_id: object) -> str | None:
    """The page for an ATT&CK or ATLAS technique id, or None for any other shape."""
    return attack_url(technique_id) or atlas_technique_url(technique_id)
