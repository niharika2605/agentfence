"""Tool registry and argument validation (Day 8).

The registry is the allowlist of tools. A tool that is not registered cannot be
called. Every registered tool has a strict argument schema: unknown arguments,
missing arguments and wrong types are all rejected (invariant I4).

Validation returns either ValidatedArguments (safe to continue) or a block
Decision. The reason text never repeats the raw value that failed.
"""
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentfence.models import Decision, ReasonCode
from agentfence.tools.simulated import (
    DEFAULT_ROWS,
    MAX_PATH,
    MAX_ROWS,
    MAX_TEXT,
    SIMULATED_TOOLS,
    Scalar,
)

STRICT_ARGS = ConfigDict(extra="forbid", strict=True, frozen=True)
MAX_REASON_PARTS = 5
MAX_NAME_CHARS = 40


class ToolRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FileReadArgs(BaseModel):
    model_config = STRICT_ARGS
    path: str = Field(min_length=1, max_length=MAX_PATH)


class EmailSendArgs(BaseModel):
    model_config = STRICT_ARGS
    to: str = Field(min_length=1, max_length=254)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=MAX_TEXT)


class DbQueryArgs(BaseModel):
    model_config = STRICT_ARGS
    table: str = Field(min_length=1, max_length=100)
    filters: dict[str, Scalar] = Field(default_factory=dict)
    limit: int = Field(default=DEFAULT_ROWS, ge=1, le=MAX_ROWS)


class CodeRunArgs(BaseModel):
    model_config = STRICT_ARGS
    code: str = Field(min_length=1, max_length=MAX_TEXT)


@dataclass(frozen=True)
class ToolSpec:
    """What the gateway knows about one tool."""

    name: str
    description: str
    args_model: type[BaseModel]
    risk: ToolRisk
    is_sink: bool = False  # sends data out of the system (used for taint checks on Day 19)


@dataclass(frozen=True)
class ValidatedArguments:
    """Arguments that passed the schema, with defaults filled in."""

    tool: str
    arguments: dict[str, Any]
    spec: ToolSpec


def _safe(text: str) -> str:
    """Keep only plain characters, so attacker text cannot ride along in a reason."""
    return re.sub(r"[^A-Za-z0-9_.\-]", "?", text)[:MAX_NAME_CHARS]


def _summarize(exc: ValidationError) -> str:
    parts: list[str] = []
    errors = exc.errors(include_url=False, include_context=False, include_input=False)
    for err in errors[:MAX_REASON_PARTS]:
        where = ".".join(_safe(str(p)) for p in err["loc"]) or "arguments"
        parts.append(f"{where} ({err['type']})")
    more = len(errors) - MAX_REASON_PARTS
    suffix = f", and {more} more" if more > 0 else ""
    return "invalid arguments: " + ", ".join(parts) + suffix


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> set[str]:
        return set(self._tools)

    def validate(
        self, call_id: str, tool: str, arguments: dict[str, Any]
    ) -> ValidatedArguments | Decision:
        spec = self._tools.get(tool)
        if spec is None:
            return Decision.block(
                call_id, ReasonCode.UNKNOWN_TOOL, f"tool is not registered: {_safe(tool)}"
            )
        try:
            model = spec.args_model.model_validate(arguments)
        except ValidationError as exc:
            return Decision.block(call_id, ReasonCode.INVALID_ARGUMENTS, _summarize(exc))
        return ValidatedArguments(tool=tool, arguments=model.model_dump(), spec=spec)


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec("file.read", "Read a file from the workspace.", FileReadArgs, ToolRisk.LOW)
    )
    registry.register(
        ToolSpec(
            "email.send", "Send an email.", EmailSendArgs, ToolRisk.HIGH, is_sink=True
        )
    )
    registry.register(
        ToolSpec("db.query", "Read rows from a table.", DbQueryArgs, ToolRisk.MEDIUM)
    )
    registry.register(
        ToolSpec("code.run", "Run code in a sandbox.", CodeRunArgs, ToolRisk.HIGH)
    )
    return registry


def registry_matches_executor(registry: ToolRegistry) -> bool:
    """True when every tool the executor can run is registered, and the reverse."""
    return registry.names() == set(SIMULATED_TOOLS)