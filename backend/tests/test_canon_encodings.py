"""Tests for the encoding decoder (Day 11)."""
import base64
from urllib.parse import quote

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from agentfence.canon.encodings import MAX_DEPTH, decode_layers
from agentfence.canon.errors import CanonicalizationError, block_for
from agentfence.canon.paths import canonicalize_path
from agentfence.canon.urls import canonicalize_url
from agentfence.models import Effect, ReasonCode


def decoded(raw: str, **kwargs: int) -> tuple[str, tuple[str, ...]]:
    result = decode_layers(raw, **kwargs)
    return result.text, result.layers


def denied(raw: object, **kwargs: int) -> None:
    with pytest.raises(CanonicalizationError):
        decode_layers(raw, **kwargs)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ---------- plain values are left alone ----------

@pytest.mark.parametrize(
    "raw",
    [
        "",
        "/workspace/public/readme.txt",
        "hello world",
        "a+b",
        "https://example.com/a?b=c&d=e",
        "me@company.com",
        "customers",
        "a\\nb",
        "C:/temp",
    ],
)
def test_plain_values_have_no_layers(raw: str) -> None:
    assert decoded(raw) == (raw, ())
    assert not decode_layers(raw).was_encoded


@pytest.mark.parametrize(
    "raw",
    [
        "quarterlyreport",
        "ThisIsAVeryLongFileName",
        "abcdefghijklmnop",
        "0123456789abcdef",
        "e3b0c44298fc1c149afbf4c8996fb924",
        "/workspace/public/readme",
        "/workspace/notes/meeting",
        "financialreport2024",
        "employeeRecordsTable",
        "projectplanfinal",
        "meetingnotesmonday",
        "customer_orders_2024",
        "user-profile-images",
    ],
)
def test_normal_names_are_not_mistaken_for_base64(raw: str) -> None:
    assert decoded(raw) == (raw, ())


# ---------- url layer ----------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%2e%2e%2fetc", "../etc"),
        ("%2E%2e/%2E%2E/etc", "../../etc"),
        ("/workspace/%2e%2e/keys", "/workspace/../keys"),
        ("%e0%a4%b0", "\u0930"),
        ("a%20b", "a b"),
        ("a%2Bb", "a+b"),
    ],
)
def test_url_layer(raw: str, expected: str) -> None:
    assert decoded(raw) == (expected, ("url",))


def test_double_and_triple_encoding_are_decoded_with_a_layer_each() -> None:
    assert decoded("%252e%252e%252f") == ("../", ("url", "url"))
    assert decoded("%25252e") == (".", ("url", "url", "url"))


def test_four_layers_are_denied_by_default() -> None:
    denied("%2525252e")


@pytest.mark.parametrize(
    "raw",
    [
        "%",
        "%zz",
        "%2",
        "100%",
        "%2g",
        "50%.txt",
        "%c0%ae%c0%ae/",
        "%ff",
        "%00",
        "%0a",
        "a%0d%0ab",
        "%e2%80%ae",
        "%2525",
    ],
)
def test_bad_percent_escapes_are_denied(raw: str) -> None:
    denied(raw)


# ---------- unicode layer ----------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\\u002e\\u002e/", "../"),
        ("\\x2e\\x2e/", "../"),
        ("\\U0000002e", "."),
        ("\\u0041\\u0042", "AB"),
        ("a\\u002fb", "a/b"),
        ("\\u0930", "\u0930"),
    ],
)
def test_unicode_layer(raw: str, expected: str) -> None:
    assert decoded(raw) == (expected, ("unicode",))


def test_url_then_unicode_layers() -> None:
    assert decoded("%5Cu002e%5Cu002e") == ("..", ("url", "unicode"))


@pytest.mark.parametrize(
    "raw",
    [
        "\\u12",
        "\\uZZZZ",
        "\\x2",
        "\\U0000002",
        "\\ud83d\\ude00",
        "\\u0000",
        "\\x0a",
        "\\U00110000",
        "\\u202e",
        "C:\\Users\\xavier",
    ],
)
def test_bad_unicode_escapes_are_denied(raw: str) -> None:
    denied(raw)


# ---------- base64 layer ----------

def test_base64_of_a_path() -> None:
    assert decoded("Li4vLi4vZXRjL3Bhc3N3ZA==") == ("../../etc/passwd", ("base64",))


def test_base64_without_padding() -> None:
    assert decoded("Li4vLi4vZXRjL3Bhc3N3ZA") == ("../../etc/passwd", ("base64",))


def test_base64_url_safe_and_standard_alphabets() -> None:
    assert decoded("Pz8_Pj4-fn5-Pz8_") == ("???>>>~~~???", ("base64",))
    assert decoded("Pz8/Pj4+fn5+Pz8/") == ("???>>>~~~???", ("base64",))


def test_base64_in_the_middle_of_a_value_is_not_decoded() -> None:
    raw = "/workspace/Li4vLi4vZXRjL3Bhc3N3ZA=="
    assert decoded(raw) == (raw, ())


@pytest.mark.parametrize(
    "raw",
    [
        "Li4v",
        "Li4vLi4v",
        "Li4vLi4vZXRjL3Bhc3N3Z===",
        "Li4vLi4vZXRjL3Bhc3N3ZA=",
        "Pz8_Pj4-fn5+Pz8/",
        "A" * 13,
        base64.b64encode(bytes(range(32))).decode(),
        base64.b64encode(b"abcdefgh\x00ijklmnop").decode(),
        base64.b64encode("caf\u00e9 caf\u00e9 caf\u00e9".encode()).decode(),
        base64.b64encode(b"\xc0\xae\xc0\xae\xc0\xae\xc0\xae").decode(),
    ],
)
def test_things_that_are_not_clean_base64_text_are_left_alone(raw: str) -> None:
    assert decoded(raw) == (raw, ())


# ---------- layers together and the depth limit ----------

def test_base64_of_url_encoding() -> None:
    raw = b64("%2e%2e%2fetc%2fpasswd")
    assert decoded(raw) == ("../etc/passwd", ("base64", "url"))


def test_base64_of_base64() -> None:
    raw = b64(b64("../../etc/passwd"))
    assert decoded(raw) == ("../../etc/passwd", ("base64", "base64"))


def test_the_depth_limit_can_be_changed() -> None:
    assert decoded("%252e", max_depth=2) == (".", ("url", "url"))
    denied("%252e", max_depth=1)
    denied("%2e", max_depth=0)
    assert decoded("plain", max_depth=0) == ("plain", ())


def test_a_negative_depth_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="max_depth"):
        decode_layers("x", max_depth=-1)


def test_default_depth_is_three() -> None:
    assert MAX_DEPTH == 3


# ---------- bad input ----------

@pytest.mark.parametrize("raw", [None, 5, b"abc", ["a"], 1.5])
def test_non_text_is_denied(raw: object) -> None:
    denied(raw)


@pytest.mark.parametrize("raw", ["a\x00b", "a\nb", "a\tb", "\u202e", "a\u200bb"])
def test_control_characters_in_the_raw_value_are_denied(raw: str) -> None:
    denied(raw)


def test_very_long_values_are_denied() -> None:
    denied("a" * 2001)


# ---------- working with the canonicalizers (decode first, then canonicalize) ----------

ROOTS = ["/workspace"]


def path_after_decoding(raw: str) -> str:
    return canonicalize_path(decode_layers(raw).text, allowed_roots=ROOTS)


@pytest.mark.parametrize(
    "raw",
    [
        "/workspace/%2e%2e/etc/passwd",
        "/workspace/%252e%252e/etc/passwd",
        "/workspace/\\u002e\\u002e/etc/passwd",
        "/workspace/%2e%2e%2f%2e%2e%2fetc",
        b64("../../etc/passwd"),
    ],
)
def test_hidden_traversal_is_caught_after_decoding(raw: str) -> None:
    with pytest.raises(CanonicalizationError):
        path_after_decoding(raw)


def test_hidden_traversal_to_a_secret_folder_shows_the_real_path() -> None:
    result = path_after_decoding("/workspace/public/%2e%2e/keys/api_keys.txt")
    assert result == "/workspace/keys/api_keys.txt"


def test_encoded_userinfo_is_caught_after_decoding() -> None:
    raw = "https://good.example%40evil.example/"
    with pytest.raises(CanonicalizationError, match="user names"):
        canonicalize_url(decode_layers(raw).text)


def test_encoded_slash_cannot_hide_a_decoy_host() -> None:
    raw = "https://evil.example%2f@good.example/"
    text = decode_layers(raw).text
    assert text == "https://evil.example/@good.example/"
    assert canonicalize_url(text).host.name == "evil.example"


def test_block_for_works_with_decoder_errors_and_hides_the_value() -> None:
    try:
        decode_layers("%2e%2e%zz-secret-token-123")
    except CanonicalizationError as exc:
        decision = block_for("c1", "path", exc)
    assert decision.effect is Effect.BLOCK
    assert decision.reason_codes == [ReasonCode.CANONICALIZATION_FAILED]
    assert "secret-token-123" not in decision.main_reason


# ---------- properties (many random inputs) ----------

ENCODED_PIECES = [
    "%", "2e", "2f", "25", "5c", "u002e", "\\", "x2e", "U0000002e", "a", "b", ".", "/",
    "Li4vLi4vZXRj", "=", "+", "-", "_", " ", "zz", "c0", "ae",
]
encoded_like = st.lists(st.sampled_from(ENCODED_PIECES), max_size=12).map("".join)
anything = st.one_of(encoded_like, st.text(max_size=80))


@settings(max_examples=500, deadline=None)
@given(anything)
def test_property_only_canonicalization_errors_are_raised(raw: str) -> None:
    try:
        decode_layers(raw)
    except CanonicalizationError:
        pass


@settings(max_examples=500, deadline=None)
@given(anything)
def test_property_the_result_is_a_fixed_point(raw: str) -> None:
    try:
        first = decode_layers(raw)
    except CanonicalizationError:
        return
    assert len(first.layers) <= MAX_DEPTH
    second = decode_layers(first.text)
    assert second.text == first.text
    assert second.layers == ()


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet="ab/. ~", min_size=1, max_size=20), st.integers(min_value=1, max_value=3))
def test_property_repeated_url_encoding_round_trips(text: str, times: int) -> None:
    assume("/" in text or " " in text)
    encoded = text
    for _ in range(times):
        encoded = quote(encoded, safe="")
    assert decoded(encoded) == (text, ("url",) * times)


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet="abc/:", min_size=8, max_size=30))
def test_property_base64_of_plain_text_round_trips(text: str) -> None:
    payload = text + "."
    assert decoded(b64(payload)) == (payload, ("base64",))


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="ab/. ", min_size=1, max_size=10))
def test_property_one_layer_too_many_is_denied(text: str) -> None:
    assume("/" in text or " " in text)
    encoded = text
    for _ in range(MAX_DEPTH + 1):
        encoded = quote(encoded, safe="")
    with pytest.raises(CanonicalizationError):
        decode_layers(encoded)