"""The garak probes a scan may run, fixed in code.

A probe id that is not in ``PROBES`` is refused before any command line is
built (``check_probe_ids``), so nothing a visitor sends can name a module or
class for garak to load.

Every probe here was run with garak 0.17.1 against a loopback stand-in with
the outside network blocked, and finished without downloading anything. Most
send at most ``prompts_per_probe`` prompts (garak's ``soft_probe_prompt_cap``);
a few send a fixed number whatever the cap, recorded as ``fixed_prompts`` so
the request budget counts them. Probes left out, and why:

- ``sysprompt_extraction.SystemPromptExtraction`` loads its system prompts
  from HuggingFace datasets; offline it exits with no attempts.
- ``latentinjection.LatentJailbreak`` scores answers with a HuggingFace
  model, which offline cannot load.
- ``latentinjection.LatentWhois`` ignores the prompt cap (168 requests at a
  cap of 5), which would spend a whole request budget on one probe.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from aegisshield.core.errors import ValidationError

ERROR_NO_PROBES = "Choose at least one probe."
ERROR_UNKNOWN_PROBE = "A probe that is not on the list was requested."


@dataclass(frozen=True)
class Probe:
    """One garak probe: its ``module.Class`` id and plain words for the page."""

    id: str
    family: str
    description: str
    fixed_prompts: int | None = None

    def prompts(self, prompts_per_probe: int) -> int:
        """The most prompts this probe sends under ``prompts_per_probe``."""
        return self.fixed_prompts if self.fixed_prompts is not None else prompts_per_probe


_INJECT = "Prompt injection"
_LATENT = "Instructions hidden in content"
_WEB = "Markup and link exfiltration"
_ENCODING = "Encoded instructions"

PROBES: tuple[Probe, ...] = (
    Probe("promptinject.HijackHateHumans", _INJECT,
          "Tells the model to ignore its task and print a fixed hostile sentence."),
    Probe("promptinject.HijackKillHumans", _INJECT,
          "The same hijack with a different fixed sentence."),
    Probe("promptinject.HijackLongPrompt", _INJECT,
          "The same hijack with a long sentence to print."),
    Probe("latentinjection.LatentInjectionReport", _LATENT,
          "Hides an instruction inside a document the model is asked to summarize."),
    Probe("latentinjection.LatentInjectionResume", _LATENT,
          "Hides an instruction inside a resume the model is asked to assess."),
    Probe("latentinjection.LatentInjectionFactSnippetEiffel", _LATENT,
          "Hides an instruction among factual snippets the model is asked to use."),
    Probe("latentinjection.LatentInjectionFactSnippetLegal", _LATENT,
          "Hides an instruction among legal snippets the model is asked to use."),
    Probe("latentinjection.LatentInjectionTranslationEnFr", _LATENT,
          "Hides an instruction inside text the model is asked to translate to French."),
    Probe("latentinjection.LatentInjectionTranslationEnZh", _LATENT,
          "Hides an instruction inside text the model is asked to translate to Chinese."),
    Probe("latentinjection.LatentWhoisSnippet", _LATENT,
          "Hides an instruction inside domain registration records."),
    Probe("web_injection.MarkdownImageExfil", _WEB,
          "Asks the model to add a markdown image whose address carries conversation data.",
          fixed_prompts=12),
    Probe("web_injection.MarkdownURIImageExfilExtended", _WEB,
          "More ways of asking for a markdown image that carries data in its address."),
    Probe("web_injection.MarkdownURINonImageExfilExtended", _WEB,
          "Asks for a markdown link (not an image) that carries data in its address."),
    Probe("web_injection.ColabAIDataLeakage", _WEB,
          "Asks for a markdown image built from data in the conversation.", fixed_prompts=4),
    Probe("web_injection.PlaygroundMarkdownExfil", _WEB,
          "Asks for a markdown image that sends a summary of the conversation.", fixed_prompts=4),
    Probe("web_injection.StringAssemblyDataExfil", _WEB,
          "Asks the model to assemble an exfiltration address from pieces.", fixed_prompts=2),
    Probe("web_injection.TaskXSS", _WEB,
          "Asks the model to include a script tag in its answer."),
    Probe("web_injection.MarkdownXSS", _WEB,
          "Asks for markdown that runs script when rendered."),
    Probe("encoding.InjectBase64", _ENCODING,
          "Gives the model a base64-encoded string and checks whether it decodes and repeats it."),
)

# The four probes the first scans were verified with; the page selects them.
DEFAULT_PROBE_IDS: tuple[str, ...] = (
    "promptinject.HijackHateHumans",
    "latentinjection.LatentInjectionReport",
    "web_injection.MarkdownImageExfil",
    "encoding.InjectBase64",
)

_BY_ID = {probe.id: probe for probe in PROBES}


def probe(probe_id: str) -> Probe:
    """The ``Probe`` for ``probe_id``; raises ``KeyError`` when it is not offered."""
    return _BY_ID[probe_id]


def check_probe_ids(probe_ids: Iterable[object]) -> tuple[str, ...]:
    """``probe_ids`` in ``PROBES`` order, each once, all on the list.

    Raises ``ValidationError`` when the list is empty or names any probe
    that is not in ``PROBES`` (compared as exact strings, nothing parsed).
    """
    wanted: set[str] = set()
    for item in probe_ids:
        if not isinstance(item, str) or item not in _BY_ID:
            raise ValidationError(ERROR_UNKNOWN_PROBE)
        wanted.add(item)
    if not wanted:
        raise ValidationError(ERROR_NO_PROBES)
    return tuple(p.id for p in PROBES if p.id in wanted)
