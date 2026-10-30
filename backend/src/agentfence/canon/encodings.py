"""Encoding decoder (Day 11).

Attackers hide '../' or a bad host inside encodings, hoping a later step decodes
them after the checks. So for fields that name a place (a path, a URL, an email
address, a table), we decode first, then canonicalize and check the result.

Three layers are understood:
- url:     %2e%2e%2f
- unicode: \\u002e  \\x2e  \\U0000002e
- base64:  Li4v...  (only if the WHOLE value is base64 for plain printable ASCII text)

Layers can be nested. Decoding stops when nothing more applies. If more than
max_depth layers apply, the value is denied. Malformed escapes are denied too.

Only use this on fields where encodings are never expected. Do not use it on
free text such as an email body or code.
"""
import base64
import binascii
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from agentfence.canon.errors import CanonicalizationError

MAX_DEPTH = 3
MAX_INPUT_CHARS = 2000
MIN_BASE64_CHARS = 12

BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
ESCAPE_START = re.compile(r"\\[uUx]")
UNICODE_ESCAPE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2}))")
BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/_-]+$")


@dataclass(frozen=True)
class DecodedValue:
    text: str
    layers: tuple[str, ...] = ()

    @property
    def was_encoded(self) -> bool:
        return bool(self.layers)


def _check_text(text: str) -> None:
    if len(text) > MAX_INPUT_CHARS:
        raise CanonicalizationError("value is too long")
    for char in text:
        if unicodedata.category(char)[0] == "C":
            raise CanonicalizationError("control or invisible characters are not allowed")


def _url_layer(text: str) -> str | None:
    if "%" not in text:
        return None
    if BAD_PERCENT.search(text):
        raise CanonicalizationError("bad percent escape")
    try:
        return unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalizationError("percent escapes are not valid text") from exc


def _replace_escape(match: re.Match[str]) -> str:
    code = int(match.group(1) or match.group(2) or match.group(3), 16)
    if code > 0x10FFFF:
        raise CanonicalizationError("unicode escape is out of range")
    return chr(code)


def _unicode_layer(text: str) -> str | None:
    starts = len(ESCAPE_START.findall(text))
    if starts == 0:
        return None
    if len(UNICODE_ESCAPE.findall(text)) != starts:
        raise CanonicalizationError("bad unicode escape")
    return UNICODE_ESCAPE.sub(_replace_escape, text)


def _base64_layer(text: str) -> str | None:
    core = text.rstrip("=")
    given_padding = len(text) - len(core)
    if len(core) < MIN_BASE64_CHARS or given_padding > 2 or not BASE64_CHARS.match(core):
        return None
    uses_standard = "+" in core or "/" in core
    uses_url_safe = "-" in core or "_" in core
    if uses_standard and uses_url_safe:
        return None
    remainder = len(core) % 4
    if remainder == 1:
        return None
    needed_padding = (4 - remainder) % 4
    if given_padding not in (0, needed_padding):
        return None
    normalized = core.replace("-", "+").replace("_", "/") + "=" * needed_padding
    try:
        raw = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return None
    # Only plain printable ASCII counts. Paths, URLs and addresses are ASCII, and
    # this keeps normal words and ids from being mistaken for base64.
    if not raw or not all(0x20 <= byte <= 0x7E for byte in raw):
        return None
    return raw.decode("ascii")


LAYERS: tuple[tuple[str, Callable[[str], str | None]], ...] = (
    ("url", _url_layer),
    ("unicode", _unicode_layer),
    ("base64", _base64_layer),
)


def decode_layers(raw: object, *, max_depth: int = MAX_DEPTH) -> DecodedValue:
    """Decode nested encodings. Returns the final text and the layers that were used."""
    if max_depth < 0:
        raise ValueError("max_depth must not be negative")
    if not isinstance(raw, str):
        raise CanonicalizationError("value must be text")
    _check_text(raw)

    current = raw
    layers: list[str] = []
    while True:
        applied: str | None = None
        for name, layer in LAYERS:
            result = layer(current)
            if result is not None:
                applied, decoded = name, result
                break
        if applied is None:
            return DecodedValue(current, tuple(layers))
        if len(layers) >= max_depth:
            raise CanonicalizationError("too many layers of encoding")
        _check_text(decoded)
        layers.append(applied)
        current = decoded