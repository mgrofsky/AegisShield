"""AegisShield threat-modeling package.

Only the ``ui`` subpackage imports ``streamlit``, so every other module can be
tested and reused without a UI.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
