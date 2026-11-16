"""Entry point: ``streamlit run main.py``.

Everything else lives in the ``aegisshield`` package; this file only starts
the app frame (navigation, theme, and pages) in ``aegisshield.ui.app``.
"""

from aegisshield.ui.app import run

run()
