"""Core data models for AgentFence (Day 6).

The agent sends a ToolCallRequest. The server builds a ToolCall from it,
adding identity and role from the session. The pipeline then produces a
Decision. A Decision cannot be built in a way that breaks the policy spec.
"""
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Namespaced tool names such as email.send. Lowercase only, so look alike
# tricks and path tricks cannot appear in a tool name.
TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$"


class Effect(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

    @property
    def strength(self) -> int:
        """Higher is stricter. Block beats approval, approval beats allow."""
        if self is Effect.BLOCK:
            return 2
        if self is Effect.REQUIRE_APPROVAL:
            return 1
        return 0


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"  # noqa: S105 (a sensitivity label, not a password)

    @property
    def rank(self) -> int:
        return list(Sensitivity).index(self)

    def at_least(self, other: Self) -> bool:
        return self.rank >= other.rank


def highest(a: Sensitivity, b: Sensitivity) -> Sensitivity:
    """The stricter of two sensitivity labels (used for the session high water mark)."""
    return a if a.rank >= b.rank else b


class TrustLevel(StrEnum):
    INTERNAL = "internal"
    ALLOWLISTED = "allowlisted"
    UNKNOWN = "unknown"


class ReasonCode(StrEnum):
    DEFAULT_DENY = "DEFAULT_DENY"
    RULE_BLOCK = "RULE_BLOCK"
    RULE_APPROVAL = "RULE_APPROVAL"
    RULE_ALLOW = "RULE_ALLOW"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    CANONICALIZATION_FAILED = "CANONICALIZATION_FAILED"

    @property
    def required_effect(self) -> Effect:
        """The one effect this code is allowed to go with."""
        return _CODE_EFFECT[self]


_CODE_EFFECT: dict[ReasonCode, Effect] = {
    ReasonCode.DEFAULT_DENY: Effect.BLOCK,
    ReasonCode.RULE_BLOCK: Effect.BLOCK,
    ReasonCode.RULE_APPROVAL: Effect.REQUIRE_APPROVAL,
    ReasonCode.RULE_ALLOW: Effect.ALLOW,
    ReasonCode.POLICY_UNAVAILABLE: Effect.BLOCK,
    ReasonCode.UNKNOWN_TOOL: Effect.BLOCK,
    ReasonCode.INVALID_ARGUMENTS: Effect.BLOCK,
    ReasonCode.CANONICALIZATION_FAILED: Effect.BLOCK,
}


class ToolCallRequest(BaseModel):
    """What the agent sends. Extra fields are dropped, never trusted (invariant I7)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    tool: str = Field(min_length=1, max_length=200, pattern=TOOL_NAME_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str = Field(min_length=1, max_length=100)


class ToolCall(BaseModel):
    """What the server builds. Identity and role come from the session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str = Field(min_length=1, max_length=100)
    user_id: str = Field(min_length=1, max_length=100)
    agent_id: str = Field(min_length=1, max_length=100)
    role: Role
    tool: str = Field(min_length=1, max_length=200, pattern=TOOL_NAME_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_request(
        cls, request: ToolCallRequest, *, user_id: str, agent_id: str, role: Role
    ) -> Self:
        return cls(
            session_id=request.session_id,
            user_id=user_id,
            agent_id=agent_id,
            role=role,
            tool=request.tool,
            arguments=request.arguments,
        )


class RuleHit(BaseModel):
    """One policy rule that matched a call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=100)
    effect: Effect
    priority: int = Field(default=100, ge=0, le=1000)
    reason: str = Field(min_length=1)


class Decision(BaseModel):
    """The result of the pipeline for one call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(min_length=1)
    effect: Effect
    reason_codes: list[ReasonCode] = Field(min_length=1)
    rule_hits: list[RuleHit] = Field(default_factory=list)
    main_reason: str = Field(min_length=1)
    policy_version: int = Field(ge=0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def check_consistency(self) -> Self:
        if self.rule_hits:
            strongest = max(hit.effect.strength for hit in self.rule_hits)
            if self.effect.strength != strongest:
                raise ValueError("effect must equal the strongest matched rule effect")
        elif self.effect is not Effect.BLOCK:
            raise ValueError("a decision with no matched rules must be block")

        for code in self.reason_codes:
            if code.required_effect is not self.effect:
                raise ValueError(
                    f"reason code {code.value} does not fit effect {self.effect.value}"
                )

        if ReasonCode.DEFAULT_DENY in self.reason_codes and self.rule_hits:
            raise ValueError("DEFAULT_DENY means no rule matched")
        return self

    @property
    def is_executable(self) -> bool:
        """Only a plain allow may reach an executor (invariant I1)."""
        return self.effect is Effect.ALLOW

    @classmethod
    def block(
        cls, call_id: str, code: ReasonCode, reason: str, policy_version: int = 0
    ) -> Self:
        """Shortcut for a block decision with no matched rules."""
        return cls(
            call_id=call_id,
            effect=Effect.BLOCK,
            reason_codes=[code],
            main_reason=reason,
            policy_version=policy_version,
        )