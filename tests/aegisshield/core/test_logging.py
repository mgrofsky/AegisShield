import logging

from aegisshield.core.logging import PACKAGE_LOGGER, configure_logging


def _ours(logger):
    return [h for h in logger.handlers if h.get_name() == "aegisshield-default"]


def test_idempotent_and_package_scoped():
    root_before = list(logging.getLogger().handlers)
    logger = configure_logging("DEBUG")
    configure_logging("warning")
    configure_logging(logging.ERROR)
    try:
        assert logger.name == PACKAGE_LOGGER
        assert len(_ours(logger)) == 1
        assert logger.level == logging.ERROR
        assert logging.getLogger().handlers == root_before
    finally:
        for handler in _ours(logger):
            logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)


def test_unknown_level_name_defaults_to_info():
    logger = configure_logging("chatty")
    try:
        assert logger.level == logging.INFO
    finally:
        for handler in _ours(logger):
            logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)




def test_import_does_not_configure_root():
    import importlib

    import aegisshield.core.logging as mod

    before = list(logging.getLogger().handlers)
    importlib.reload(mod)
    assert logging.getLogger().handlers == before
