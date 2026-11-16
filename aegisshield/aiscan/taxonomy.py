"""MITRE ATLAS techniques for each offered garak probe, kept by this app.

garak tags its probes with OWASP LLM and AVID references (read from its
report, ``report.ParsedReport.tags_for``) but not with ATLAS ones, so this
table maps each probe in ``probes.PROBES`` to one or more ATLAS technique
ids, each with a one-line reason. It says which technique a probe's prompts
attempt; it is not a finding, and it never affects a scan's status.

Every id and name comes from the app's bundled ATLAS catalog
(``catalog_service.load_atlas_entries``, the official release recorded in
``aegisshield/data/atlas/SOURCE.md``); a test checks each id is in it. The
choice of technique for each probe is this app's own reading of what the
probe's prompts attempt, not MITRE's or garak's.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisshield.pipeline.catalog_service import load_atlas_entries

ATLAS_URL = "https://atlas.mitre.org/techniques/{id}"

_USED_IDS = ("AML.T0051.000", "AML.T0051.001", "AML.T0068", "AML.T0077")


def _names() -> dict[str, str]:
    """Each used id's name from the catalog; a sub-technique carries its parent's name first."""
    by_id = {entry.technique_id: entry.name for entry in load_atlas_entries()}
    names: dict[str, str] = {}
    for technique_id in _USED_IDS:
        parent = technique_id.rsplit(".", 1)[0] if technique_id.count(".") == 2 else ""
        own = by_id[technique_id]
        names[technique_id] = f"{by_id[parent]}: {own}" if parent else own
    return names


# The name of each ATLAS technique the table uses, read from the catalog.
ATLAS_NAMES: dict[str, str] = _names()


@dataclass(frozen=True)
class AtlasRef:
    """One ATLAS technique a probe's prompts attempt, and why."""

    id: str
    reason: str

    @property
    def name(self) -> str:
        """The technique's name."""
        return ATLAS_NAMES[self.id]

    @property
    def url(self) -> str:
        """The technique's page on atlas.mitre.org."""
        return ATLAS_URL.format(id=self.id)


_DIRECT_HIJACK = AtlasRef("AML.T0051.000", "The instruction to drop the task is in the user's own message.")
_HIDDEN = AtlasRef("AML.T0051.001", "The instruction is hidden in content the model is asked to process.")
_LEAK = AtlasRef("AML.T0077", "The answer is asked to carry conversation data out in a link or image address.")

ATLAS_BY_PROBE: dict[str, tuple[AtlasRef, ...]] = {
    "promptinject.HijackHateHumans": (_DIRECT_HIJACK,),
    "promptinject.HijackKillHumans": (_DIRECT_HIJACK,),
    "promptinject.HijackLongPrompt": (_DIRECT_HIJACK,),
    "latentinjection.LatentInjectionReport": (_HIDDEN,),
    "latentinjection.LatentInjectionResume": (_HIDDEN,),
    "latentinjection.LatentInjectionFactSnippetEiffel": (_HIDDEN,),
    "latentinjection.LatentInjectionFactSnippetLegal": (_HIDDEN,),
    "latentinjection.LatentInjectionTranslationEnFr": (_HIDDEN,),
    "latentinjection.LatentInjectionTranslationEnZh": (_HIDDEN,),
    "latentinjection.LatentWhoisSnippet": (_HIDDEN,),
    "web_injection.MarkdownImageExfil": (_HIDDEN, _LEAK),
    "web_injection.MarkdownURIImageExfilExtended": (_HIDDEN, _LEAK),
    "web_injection.MarkdownURINonImageExfilExtended": (_HIDDEN, _LEAK),
    "web_injection.ColabAIDataLeakage": (_HIDDEN, _LEAK),
    "web_injection.PlaygroundMarkdownExfil": (_HIDDEN, _LEAK),
    "web_injection.StringAssemblyDataExfil": (_HIDDEN, _LEAK),
    "web_injection.TaskXSS": (AtlasRef("AML.T0051.000", "The message asks for a script tag in the answer."),),
    "web_injection.MarkdownXSS": (AtlasRef("AML.T0051.000",
                                           "The message asks for markdown that runs script when shown."),),
    "encoding.InjectBase64": (AtlasRef("AML.T0051.000",
                                       "The message hides its instruction in base64 for the model to decode."),
                              AtlasRef("AML.T0068", "The instruction is encoded so a filter reading plain text misses it.")),
}


def atlas_for(probe_id: str) -> tuple[AtlasRef, ...]:
    """The ATLAS techniques for ``probe_id``; empty for a probe not in the table."""
    return ATLAS_BY_PROBE.get(probe_id, ())


def atlas_record(probe_id: str) -> list[dict[str, str]]:
    """The ATLAS references for ``probe_id`` as plain JSON values for a scan record."""
    return [{"id": ref.id, "name": ref.name, "reason": ref.reason} for ref in atlas_for(probe_id)]
