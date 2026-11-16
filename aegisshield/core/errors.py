"""The package's exception hierarchy.

Every message is a plain sentence that is safe to show a visitor. Code that
wraps a provider SDK error raises one of these with a fixed message and keeps
the original only as ``__cause__`` for the log.
"""

from __future__ import annotations


class AegisError(Exception):
    """Base class for every error this package raises on purpose."""


class ConfigurationError(AegisError):
    """A setting or input needed to start the work is missing or invalid."""


class ValidationError(AegisError):
    """Input from a visitor or a file failed validation."""


class LLMError(AegisError):
    """The language model could not be reached or did not answer."""


class LLMResponseError(LLMError):
    """The model answered, but the answer is unreadable or was cut short."""


class IntelLookupError(AegisError):
    """A threat-intelligence lookup (NVD, OTX, KEV, EPSS) failed."""


class JobError(AegisError):
    """A background job could not be started or managed."""


class WorkspaceError(AegisError):
    """A workspace could not be loaded, validated, or saved."""


__all__ = [
    "AegisError",
    "ConfigurationError",
    "IntelLookupError",
    "JobError",
    "LLMError",
    "LLMResponseError",
    "ValidationError",
    "WorkspaceError",
]
