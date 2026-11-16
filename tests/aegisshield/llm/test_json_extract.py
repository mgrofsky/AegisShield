import pytest

from aegisshield.core.errors import LLMResponseError
from aegisshield.llm.json_extract import extract_json


@pytest.mark.parametrize(
    "raw",
    [
        '{"a": 1}',
        '  {"a": 1}  ',
        '```json\n{"a": 1}\n```',
        '```\n{"a": 1}\n```',
        '```{"a": 1}```',
        'Here is the result:\n{"a": 1}\nThanks.',
        'Sure.\n```json\n{"a": 1}\n```',
    ],
)
def test_reads_object(raw):
    assert extract_json(raw) == {"a": 1}


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        '{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "cut off',
        "no json here",
        "} backwards {",
        '{"a": {"b": 1}',
        "[1, 2, 3]",
        '"just a string"',
    ],
)
def test_unreadable_raises(raw):
    with pytest.raises(LLMResponseError):
        extract_json(raw)
