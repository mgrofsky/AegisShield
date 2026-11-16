"""Logging setup for the package.

Nothing in the package configures logging at import. The app calls
``configure_logging()`` once at start; calling it again only updates the
level. The handler goes on the ``aegisshield`` logger, not the root logger,
so it never fights Streamlit's own logging setup.
"""

from __future__ import annotations

import logging

PACKAGE_LOGGER = "aegisshield"
_HANDLER_NAME = "aegisshield-default"
_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging(level: str | int = "INFO") -> logging.Logger:
    """Attach one stream handler to the package logger and set its level.

    Safe to call many times: the handler is added once, and later calls
    only change the level. Returns the package logger.
    """
    logger = logging.getLogger(PACKAGE_LOGGER)
    if isinstance(level, str):
        level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
    logger.setLevel(level)
    if not any(h.get_name() == _HANDLER_NAME for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.set_name(_HANDLER_NAME)
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
    return logger


