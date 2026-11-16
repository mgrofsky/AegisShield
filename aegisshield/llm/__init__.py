"""Language model access.

Services receive an ``LLMClient`` instead of calling a module-level client,
because each visitor brings their own model provider credential. Use
``get_llm`` to build one, and ``aegisshield.llm.providers`` for the providers,
the credential, and the live model list.
"""

from aegisshield.llm.base import LLMClient, OnText
from aegisshield.llm.factory import get_llm

__all__ = ["LLMClient", "OnText", "get_llm"]
