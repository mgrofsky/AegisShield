import builtins

from aegisshield.core import errors


def test_hierarchy():
    assert issubclass(errors.LLMResponseError, errors.LLMError)
    for name in errors.__all__:
        assert issubclass(getattr(errors, name), errors.AegisError)


def test_no_builtin_shadowed():
    for name in errors.__all__:
        assert not hasattr(builtins, name)
    assert not issubclass(errors.IntelLookupError, builtins.LookupError)
