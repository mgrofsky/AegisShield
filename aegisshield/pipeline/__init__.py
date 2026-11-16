"""The threat-model pipeline: lookups, prompts, the linear and agentic paths.

``run_threat_model`` (in ``run``) is the entry point the page submits to the
job runner. Modules are one per service, kept flat.
"""

from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import AppProfile, ThreatModelRequest

__all__ = ["AppProfile", "ThreatModelRequest", "run_threat_model"]
