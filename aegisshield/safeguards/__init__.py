"""Checks on the app's own model calls, built on NVIDIA NeMo Guardrails.

One ``Safeguards`` object serves one job and holds only that job's record:

- ``screen(source, text)`` checks text that is about to enter a prompt and
  returns the text to use. Text the visitor typed (``Source.DESCRIPTION``,
  ``PROFILE``, ``POLICY``) goes through the input rails; text from anywhere
  else goes through the retrieved-content rails.
- ``wrap(llm)`` returns a client whose every call passes the output rails.
- ``report()`` is a JSON-safe record of every check this object ran.

``Safeguards.from_settings(settings)`` follows ``AEGIS_SAFEGUARDS`` and
``AEGIS_SAFEGUARDS_STRICT``. When safeguards are off, every method is a pass
through that records nothing. ``safeguards_status(settings)`` says whether
they are on, off, or unavailable (NeMo Guardrails not installed), with
versions, and carries no visitor data.

The checks look for an instruction addressed to the model in a place where
no instruction belongs, and for leakage in an answer. They do not look for
security vocabulary, and they do not judge whether an answer is correct.
"""

from __future__ import annotations

import os

# NeMo Guardrails sends usage statistics to its vendor unless this is set
# before its first use. This package is the only importer of NeMo in the app,
# and it sets the variable on import, overriding any other value on purpose.
os.environ["NEMO_GUARDRAILS_NO_USAGE_STATS"] = "1"

from aegisshield.safeguards.core import (  # noqa: E402
    BLOCKED_INJECTION,
    BLOCKED_LEAK,
    CHECK_TIME_LIMIT_SECONDS,
    JOB_ERRORS,
    MAX_ABANDONED_CHECKS,
    NOT_CHECKED_ANSWER,
    NOT_CHECKED_INPUT,
    REPORT_KEY,
    TOO_MANY_STUCK,
    CheckStatus,
    RailSet,
    Safeguards,
    SafeguardsStopped,
    Source,
    safeguards_status,
)

__all__ = [
    "BLOCKED_INJECTION",
    "BLOCKED_LEAK",
    "CHECK_TIME_LIMIT_SECONDS",
    "JOB_ERRORS",
    "MAX_ABANDONED_CHECKS",
    "NOT_CHECKED_ANSWER",
    "NOT_CHECKED_INPUT",
    "REPORT_KEY",
    "CheckStatus",
    "RailSet",
    "Safeguards",
    "SafeguardsStopped",
    "Source",
    "TOO_MANY_STUCK",
    "safeguards_status",
]
