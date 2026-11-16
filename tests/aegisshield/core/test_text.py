import pytest

from aegisshield.core import text


def test_clean_text_removes_c0_keeps_tab_newline():
    assert text.clean_text("a\x00b\x07c\td\ne\x1f") == "abc\td\ne"
    assert text.clean_text(None) == ""




def test_strip_invisible():
    raw = "a\u200bb\u200fc\ufeffd\x7fe\x85f\u2028g\u202ah\u061ci"
    assert text.strip_invisible(raw) == "abcdefghi"
    assert text.strip_invisible(None) == ""


@pytest.mark.parametrize(
    ("value", "limit", "expected"),
    [
        ("short", 10, "short"),
        ("the quick brown fox", 12, "the quick..."),
        ("abcdefghijkl", 8, "abcde..."),
        ("abcdef", 3, "abc"),
        ("abcdef", 0, ""),
        ("  padded\x00  ", 20, "padded"),
    ],
)
def test_clip_words(value, limit, expected):
    assert text.clip_words(value, limit) == expected


@pytest.mark.parametrize(
    ("value", "limit", "expected"),
    [
        ("short", 10, "short"),
        ("alpha beta gamma delta", 12, "...delta"),
        ("alpha beta gamma delta", 9, "...delta"),
        ("abcdefghijkl", 8, "...hijkl"),
        ("abcdef", 2, "ef"),
        ("abcdef", 0, ""),
    ],
)
def test_clip_tail(value, limit, expected):
    assert text.clip_tail(value, limit) == expected


def test_clip_tail_on_word_boundary_keeps_cut():
    assert text.clip_tail("aaaa bbbb", 7) == "...bbbb"


def test_single_line():
    assert text.single_line("Line one\nline\ttwo\u202e", 100) == "Line one line two"
    assert text.single_line(42, 10) == ""
    assert text.single_line("word " * 50, 20).endswith("...")


def test_sanitize_user_markdown():
    raw = "\ufeff# Title\r\nbody\x00 text\u200b\rnext\u2029end\u202e  "
    assert text.sanitize_user_markdown(raw) == "# Title\nbody text\nnext\nend"
    assert text.sanitize_user_markdown(None) == ""
    clipped = text.sanitize_user_markdown("one two three four", max_chars=10)
    assert clipped == "one two..."


def test_redact_keys():
    secret = "sk-proj-abcdefghijklmnop"
    msg = f"Incorrect API key provided: {secret}. Bearer abcdefghijklmnop"
    out = text.redact_keys(msg)
    assert secret not in out and "abcdefghijklmnop" not in out
    assert text.redact_keys("token mysecret here", "mysecret") == "token [redacted] here"
    assert text.redact_keys(None, "") == ""


# The two Bedrock API key shapes AWS documents (AWS Security Blog, "Securing
# Amazon Bedrock API keys"): long-term keys start "ABSKQmVkcm9ja0FQSUtleS"
# and short-term keys start "bedrock-api-key-". Built from parts so a
# secret scanner does not flag this file.
_LONG_TERM = "ABSK" + "QmVkcm9ja0FQSUtleS" + "abc+/9" * 20 + "="
_SHORT_TERM = "bedrock-api-key-" + "YmVk+/" * 30 + "=="


@pytest.mark.parametrize("key", [_LONG_TERM, _SHORT_TERM])
def test_redact_keys_removes_bedrock_api_keys_whole(key):
    out = text.redact_keys(f"denied for {key} today")
    assert out == "denied for [redacted] today"


# Key shapes that are only keys in context: an AWS secret access key (40
# base64 characters), an NVD key (a UUID), and an OTX key (64 hex). Built
# from parts so a secret scanner does not flag this file.
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_NVD_KEY = "0b5c3a3e-" + "7c1d-4f7e-9a51-2f6c9d8e1a77"
_OTX_KEY = "9f86d081884c7d659a2feaa0c55ad015" + "a3bf4f1b2b0b822cd15d6c15b0f00a08"


@pytest.mark.parametrize("labeled", [
    f"aws_secret_access_key={_AWS_SECRET}",
    f"SecretAccessKey: {_AWS_SECRET}",
    f"secret_access_key = '{_AWS_SECRET}'",
    f"headers {{'apiKey': '{_NVD_KEY}'}}",
    f"GET /rest/json/cves/2.0?apiKey={_NVD_KEY}&x=1",
    f"{{'X-OTX-API-KEY': '{_OTX_KEY}'}}",
    f"otx_api_key: {_OTX_KEY}",
    f"api_key=\"{_OTX_KEY}\"",
])
def test_redact_keys_removes_a_labeled_key_value(labeled):
    out = text.redact_keys(f"request failed: {labeled} (status 403)")
    assert _AWS_SECRET not in out and _NVD_KEY not in out and _OTX_KEY not in out
    assert "[redacted]" in out and out.startswith("request failed: ") and out.endswith(" (status 403)")


def test_redact_keys_leaves_unlabeled_ids_and_hashes():
    plain = (f"CVE record {_NVD_KEY} has sha256 {_OTX_KEY}; "
             "the api_key field is required; token expired")
    assert text.redact_keys(plain) == plain


def test_redact_keys_removes_the_callers_secrets_whatever_their_shape():
    out = text.redact_keys(f"bad {_NVD_KEY} and {_OTX_KEY} and {_AWS_SECRET}", _NVD_KEY, _OTX_KEY, _AWS_SECRET)
    assert out == "bad [redacted] and [redacted] and [redacted]"


def test_redact_keys_is_linear_on_labels():
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    for hostile in ("api_key=" * 40_000, "apiKey: '" * 30_000, "secret_access_key " * 20_000,
                    "X-OTX-API-KEY'" + " " * 300_000, "token=" + "a" * 300_000):
        assert least_stall(text.redact_keys, hostile, repeats=2).stall < STALL_LIMIT_S


def test_redact_keys_is_linear_on_bedrock_prefixes():
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    for hostile in ("bedrock-api-key-" * 20_000, "ABSK" + "QmVkcm9ja0FQSUtleS" + "+" * 300_000):
        assert least_stall(text.redact_keys, hostile, repeats=2).stall < STALL_LIMIT_S
