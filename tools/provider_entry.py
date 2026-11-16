"""The real app outside mock mode with every model provider faked, for
browser checks of the provider and model controls.

    streamlit run tools/provider_entry.py

``tools/browser_check.py --only providers`` starts the app through this
file. Like ``tools/mock_entry.py`` it first installs the lookup fakes, so
nothing reaches the network. Then:

- ``providers.list_models`` answers from
  ``tests/aegisshield/ui/provider_page_fakes.py`` for any credential, so
  each provider's model select box fills without a real key.
- ``factory._build`` returns the canned mock for every provider, so a run
  started in this mode completes, answered by canned text while it records
  the chosen provider and model. No provider SDK client is built.
- AI workflow scans are on (``AEGIS_AI_SCAN=1`` unless already set), with
  the scan tests' fake garak unless ``AEGIS_GARAK_PYTHON`` names a real
  garak environment, so a scan with the "real" model runs through the
  chosen provider's (canned) client.

Use it only for checks.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.llm import factory, providers  # noqa: E402
from aegisshield.llm.mock import MockLLM  # noqa: E402
from aegisshield.ui import app  # noqa: E402
from tests.aegisshield.aiscan import garak_fakes  # noqa: E402
from tests.aegisshield.ui import lookup_fakes  # noqa: E402
from tests.aegisshield.ui.provider_page_fakes import FakeModelLists  # noqa: E402

if not getattr(lookup_fakes, "_provider_check_installed", False):
    lookup_fakes.install(delay=float(os.environ.get("CHECK_NVD_DELAY", "0.2")))
    providers.list_models = FakeModelLists()
    factory._build = lambda _provider, _cred: MockLLM()
    if not os.environ.get("AEGIS_GARAK_PYTHON"):
        fake = garak_fakes.install(Path(tempfile.mkdtemp(prefix="aegis-fake-garak-")) / "env")
        os.environ["AEGIS_GARAK_PYTHON"] = fake.python
    os.environ.setdefault("AEGIS_AI_SCAN", "1")
    lookup_fakes._provider_check_installed = True

app.run()
