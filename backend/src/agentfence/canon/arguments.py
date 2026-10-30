"""The canonicalization chain for a whole tool call (Day 12).

Order of work for one call:
1. Validate the arguments against the tool schema (Day 8).
2. For each field that names a place (a path, URL, email address or table):
   decode nested encodings (Day 11), then canonicalize (Days 9 and 10).
3. Return the canonical arguments, or a block Decision.

Free text fields (an email body, code) are left exactly as they are.
The caller must run the canonical arguments, never the raw ones.
"""
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from agentfence.canon.encodings import decode_layers
from agentfence.canon.errors import CanonicalizationError, block_for
from agentfence.canon.paths import DEFAULT_BASE, canonicalize_path
from agentfence.canon.urls import canonicalize_email, canonicalize_url
from agentfence.models import Decision, ReasonCode
from agentfence.tools.registry import ToolRegistry, ToolSpec, ValidatedArguments

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class Locator(StrEnum):
    """What kind of place a field names. It decides which canonicalizer runs."""

    PATH = "path"
    URL = "url"
    EMAIL = "email"
    NAME = "name"


# Every registered tool needs an entry, even if it has no location fields.
DEFAULT_LOCATORS: dict[str, dict[str, Locator]] = {
    "file.read": {"path": Locator.PATH},
    "email.send": {"to": Locator.EMAIL},
    "db.query": {"table": Locator.NAME},
    "code.run": {},
}


@dataclass(frozen=True)
class CanonConfig:
    allowed_roots: tuple[str, ...] = ("/workspace",)
    symlinks: Mapping[str, str] = field(default_factory=dict)
    base: str = DEFAULT_BASE
    fold_case: bool = False


@dataclass(frozen=True)
class CanonicalArguments:
    tool: str
    arguments: dict[str, Any]
    encoded: dict[str, tuple[str, ...]]  # field name -> layers that were decoded
    spec: ToolSpec

    @property
    def was_encoded(self) -> bool:
        return bool(self.encoded)


def canonicalize_name(text: str) -> str:
    """A table or similar name: lowercase letters, digits and underscores only."""
    if not NAME_PATTERN.match(text):
        raise CanonicalizationError("name has unsupported characters")
    return text


def _canonicalize_value(kind: Locator, text: str, config: CanonConfig) -> str:
    if kind is Locator.PATH:
        return canonicalize_path(
            text,
            allowed_roots=config.allowed_roots,
            symlinks=config.symlinks,
            base=config.base,
            fold_case=config.fold_case,
        )
    if kind is Locator.URL:
        return canonicalize_url(text).text
    if kind is Locator.EMAIL:
        return canonicalize_email(text).text
    return canonicalize_name(text)


def canonicalize_call(
    registry: ToolRegistry,
    call_id: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    config: CanonConfig | None = None,
    locators: Mapping[str, Mapping[str, Locator]] | None = None,
) -> CanonicalArguments | Decision:
    config = config or CanonConfig()
    table = DEFAULT_LOCATORS if locators is None else locators

    checked = registry.validate(call_id, tool, arguments)
    if not isinstance(checked, ValidatedArguments):
        return checked

    rules = table.get(tool)
    if rules is None:  # a registered tool without rules is a setup bug: fail closed
        return Decision.block(
            call_id, ReasonCode.CANONICALIZATION_FAILED, "no canonicalization rules for this tool"
        )

    result = dict(checked.arguments)
    encoded: dict[str, tuple[str, ...]] = {}
    for name, kind in rules.items():
        if result.get(name) is None:  # an optional field that was not given
            continue
        try:
            decoded = decode_layers(result[name])
            result[name] = _canonicalize_value(kind, decoded.text, config)
        except CanonicalizationError as exc:
            return block_for(call_id, name, exc)
        if decoded.layers:
            encoded[name] = decoded.layers
    return CanonicalArguments(tool=tool, arguments=result, encoded=encoded, spec=checked.spec)