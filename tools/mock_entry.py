"""The real app with every outside source stubbed, for browser checks.

    AEGIS_MOCK_LLM=1 streamlit run tools/mock_entry.py

``tools/browser_check.py`` starts the app through this file. Before the real
``aegisshield.ui.app.run()`` it installs, once per process, the fakes the
page tests use:

- ``tests/aegisshield/ui/lookup_fakes.py``: NVD and OTX answered from a
  table, the CISA KEV, ExploitDB, and endoflife.date caches seeded, EPSS
  answered from a table, and ``requests.get`` made to fail, so nothing
  reaches the network. Each NVD answer waits ``CHECK_NVD_DELAY`` seconds
  (default 1.5) so the running lookup can be seen.
- ``tests/aegisshield/ui/pcap_fakes.py``: when no real ``tshark`` is on PATH,
  the services tests' fake ``tshark`` (hand-written fixtures) goes first on
  PATH, so the capture page can run. ``CHECK_REAL_TSHARK=1`` refuses the
  fake and leaves the page hidden when the real binary is missing.
- ``tests/aegisshield/aiscan/garak_fakes.py``: AI workflow scans are turned
  on (``AEGIS_AI_SCAN=1`` unless already set). Unless ``AEGIS_GARAK_PYTHON``
  names a real garak environment, the scan tests' fake garak interpreter is
  used, which answers each request after ``CHECK_GARAK_DELAY`` seconds
  (default 0.3) so the running scan can be seen.

The model is the mock (``AEGIS_MOCK_LLM=1``). Use it only for checks.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.ui import app  # noqa: E402
from tests.aegisshield.aiscan import garak_fakes  # noqa: E402
from tests.aegisshield.ui import lookup_fakes, pcap_fakes  # noqa: E402

if not getattr(lookup_fakes, "_check_installed", False):
    lookup_fakes.install(delay=float(os.environ.get("CHECK_NVD_DELAY", "1.5")))
    if not shutil.which("tshark") and os.environ.get("CHECK_REAL_TSHARK") != "1":
        fake_dir = Path(tempfile.mkdtemp(prefix="aegis-fake-tshark-"))
        os.environ["PATH"] = pcap_fakes.install(fake_dir, sleep=0.5)
        os.environ["CHECK_FAKE_TSHARK"] = "1"
    if not os.environ.get("AEGIS_GARAK_PYTHON"):
        fake = garak_fakes.install(Path(tempfile.mkdtemp(prefix="aegis-fake-garak-")) / "env")
        fake.configure(mode="slow", sleep=float(os.environ.get("CHECK_GARAK_DELAY", "0.3")))
        os.environ["AEGIS_GARAK_PYTHON"] = fake.python
        os.environ["CHECK_FAKE_GARAK"] = "1"
    os.environ.setdefault("AEGIS_AI_SCAN", "1")
    lookup_fakes._check_installed = True

app.run()
