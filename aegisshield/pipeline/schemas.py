"""The threat-model request and the application profile it carries.

Notes on the request:

- No API keys and no model name in the request. Keys are passed by value to
  ``run_threat_model`` so they never sit in a stored request, and the model
  comes from ``Settings``.
- ``technical_ability`` accepts Low, Medium, or High, as the prompt describes.
- ``agentic`` lets one request ask for the agentic path.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

AddOn = Literal["mitigations", "dread", "test_cases"]
TechnicalAbility = Literal["Low", "Medium", "High"]

ADDON_ORDER: tuple[AddOn, ...] = ("mitigations", "dread", "test_cases")

# Limits on visitor text that goes into a model prompt. The wizard checks the
# first two with a sentence of its own; the request enforces all of them, so
# text that did not come through the wizard's widgets is refused too.
MAX_DESCRIPTION_CHARS = 20_000
MAX_DIAGRAM_TEXT_CHARS = 10_000
# The description plus the reviewed diagram description and its heading.
MAX_APP_DESCRIPTION_CHARS = MAX_DESCRIPTION_CHARS + MAX_DIAGRAM_TEXT_CHARS + 200
# Every profile value is a choice from a list or a short version string, and
# no list can be longer than the option list it is chosen from (the largest,
# the technology catalog, has under 200 entries; a test keeps it so).
MAX_PROFILE_VALUE_CHARS = 200
MAX_PROFILE_ITEMS = 500

_Value = Annotated[str, StringConstraints(max_length=MAX_PROFILE_VALUE_CHARS)]
_Values = Annotated[list[_Value], Field(max_length=MAX_PROFILE_ITEMS)]
_Pairs = Annotated[dict[_Value, _Value], Field(max_length=MAX_PROFILE_ITEMS)]


class AppProfile(BaseModel):
    """What the visitor told us about the application and the organization."""

    model_config = ConfigDict(extra="ignore")

    app_type: _Value = Field(..., min_length=1)
    industry_sector: _Value = Field(..., min_length=1)
    sensitive_data: _Value = Field(..., min_length=1)
    internet_facing: _Value = Field(..., min_length=1)
    num_employees: _Value = Field(default="Unknown")
    compliance_requirements: _Values = Field(default_factory=list)
    technical_ability: TechnicalAbility = "Medium"
    authentication: _Values = Field(default_factory=list)
    # Technology name to NVD CPE prefix, and technology name to version.
    selected_technologies: _Pairs = Field(default_factory=dict)
    selected_versions: _Pairs = Field(default_factory=dict)
    # Architectural pattern tags ("GenAI", "RAG", "Agentic", "Tool Use",
    # "Code Execution", "ML") that attach OWASP and ATLAS reference cards to
    # the prompt. Pattern detection fills them in when this is empty.
    app_pattern: _Values = Field(default_factory=list)


class ThreatModelRequest(BaseModel):
    """One threat-model run, as the page submits it."""

    model_config = ConfigDict(extra="forbid")

    app_profile: AppProfile
    app_description: str = Field(..., min_length=20, max_length=MAX_APP_DESCRIPTION_CHARS)
    architecture_image_base64: str | None = None
    addons: list[AddOn] | None = Field(
        default=None,
        description=(
            "Add-ons the run does itself after the core stages, in the order "
            "mitigations, DREAD, test cases. None leaves them to the page (their "
            "stages stay queued). A list, even empty, means the run does the "
            "listed add-ons and skips the rest. Ignored on the agentic path, "
            "where the Lead plans the sections."
        ),
    )
    agentic: bool = False
    # Where the wizard's text came from when it did not start empty: a
    # vulnerability lookup's hand-off, or a saved (possibly imported) record
    # run again. The safeguards screen such text as lookup or imported
    # content as well as, or instead of, typed text.
    prefilled_from: Literal["lookup", "record"] | None = None


__all__ = [
    "ADDON_ORDER",
    "MAX_APP_DESCRIPTION_CHARS",
    "MAX_DESCRIPTION_CHARS",
    "MAX_DIAGRAM_TEXT_CHARS",
    "MAX_PROFILE_ITEMS",
    "MAX_PROFILE_VALUE_CHARS",
    "AddOn",
    "AppProfile",
    "TechnicalAbility",
    "ThreatModelRequest",
]
