"""A fake ``tshark`` on PATH for the PCAP page tests and the browser evidence.

Reuses the services tests' ``fake_tshark.py`` and hand-written fixtures, so
the page runs the real subprocess path without the binary.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[1] / "services"
FIXTURES = SERVICES / "fixtures"
MINIMAL_PCAP = FIXTURES / "minimal.pcap"

# VoIP statistics plus every field table, so every section has rows.
SCENARIO = {
    "stats": {"io,phs": "phs_voip.txt", "conv,ip": "conv_voip.txt", "rtp,streams": "rtp_voip.txt"},
    "fields": {
        "sip": "sip_voip.tsv",
        "dns.flags.response == 0": "dns_web.tsv",
        "tls.handshake.type == 1": "tls_web.tsv",
        "http.request": "http_web.tsv",
    },
}


def install(bin_dir: Path, *, sleep: float = 0.0, fixtures: Path | None = None) -> str:
    """Write the fake binary into ``bin_dir`` and return the PATH to use."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "tshark"
    script.write_text(f"#!{sys.executable}\n" + (SERVICES / "fake_tshark.py").read_text())
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    config = {"fixtures": str(fixtures or FIXTURES / "tshark"), **SCENARIO, "sleep": sleep}
    (bin_dir / "config.json").write_text(json.dumps(config))
    return f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
