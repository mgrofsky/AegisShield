"""AI workflow scans: NVIDIA garak run against AegisShield's own workflow.

An operator turns scans on (``AEGIS_AI_SCAN``) and names the Python of an
environment where garak is installed (``AEGIS_GARAK_PYTHON``). A scan runs
garak as a subprocess against a loopback shim that answers each prompt
through one of the app's own workflow steps (``surfaces``), and stores what
garak sent, what the step answered, and what each detector decided.

The only targets are the surfaces fixed in code. No address a visitor types
is ever contacted, and nothing here assesses an outside endpoint.
"""

from aegisshield.aiscan.availability import Availability, ScanState, scan_availability
from aegisshield.aiscan.limits import ScanLimits
from aegisshield.aiscan.probes import DEFAULT_PROBE_IDS, PROBES, Probe
from aegisshield.aiscan.report import ProbeState, ScanStatus
from aegisshield.aiscan.service import ScanRequest, run_scan
from aegisshield.aiscan.shim import SurfaceRefused

__all__ = [
    "DEFAULT_PROBE_IDS",
    "PROBES",
    "Availability",
    "Probe",
    "ProbeState",
    "ScanLimits",
    "ScanRequest",
    "ScanState",
    "ScanStatus",
    "SurfaceRefused",
    "run_scan",
    "scan_availability",
]
