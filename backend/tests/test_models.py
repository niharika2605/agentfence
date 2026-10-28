"""Tests for the core models (Day 6)."""
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentfence.models import (
    Decision,
    Effect,
    ReasonCode,
    Role,
    RuleHit,
    Sensitivity,
    ToolCall,
    ToolCallRequest,
    TrustLevel,
    highest,
)

SPEC = Path(__file__).resolve().parents[2] / "docs" / "policy_spec.md"


def hit(effect: Effect, rule_id: str = "r1") -> RuleHit:
    return RuleHit(rule_id=rule_id, effect=effect, reason="Because.")


def make_decision(**overrides: Any) -> Decision:
    data: dict[str, Any] = {
        "call_id": "c1",
        "effect": Effect.BLOCK,
        "reason_codes": [ReasonCode.DEFAULT_DENY],
        "main_reason": "No rule matched.",
        "policy_version": 1,
    }
    data.update(overrides)
    return Decision(**data)


def make_call(**overrides: Any) -> ToolCall:
    data: dict[str, Any] = {
        "session_id": "s1",
        "user_id": "u1",
        "agent_id": "a1",
        "role": Role.VIEWER,
        "tool": "file.read",
        "arguments": {},
    }
    data.update(overrides)
    return ToolCall(**data)


# Enums match the policy spec

def test_effect_values_match_policy_spec() -> None:
    assert {e.value for e in Effect} == {"allow", "require_approval", "block"}


def test_effect_strength_order() -> None:
    assert Effect.ALLOW.strength < Effect.REQUIRE_APPROVAL.strength < Effect.BLOCK.strength


def test_role_values() -> None:
    assert {r.value for r in Role} == {"viewer", "operator", "administrator"}


def test_sensitivity_order_matches_spec() -> None:
    assert [s.value for s in Sensitivity] == ["public", "internal", "confidential", "secret"]
    assert Sensitivity.SECRET.at_least(Sensitivity.CONFIDENTIAL)
    assert not Sensitivity.PUBLIC.at_least(Sensitivity.INTERNAL)


def test_highest_returns_the_stricter_label() -> None:
    assert highest(Sensitivity.INTERNAL, Sensitivity.SECRET) is Sensitivity.SECRET
    assert highest(Sensitivity.CONFIDENTIAL, Sensitivity.PUBLIC) is Sensitivity.CONFIDENTIAL


def test_trust_level_values() -> None:
    assert {t.value for t in TrustLevel} == {"internal", "allowlisted", "unknown"}


# Requests and calls (invariant I7)

def test_request_ignores_client_supplied_decision_fields() -> None:
    req = ToolCallRequest.model_validate(
        {
            "tool": "email.send",
            "arguments": {"to": "a@b.com"},
            "session_id": "s1",
            "allow": True,
            "decision": "allow",
            "approved": True,
            "role": "administrator",
            "user_id": "someone-else",
        }
    )
    assert set(req.model_dump()) == {"tool", "arguments", "session_id"}


def test_server_assigns_identity_not_client() -> None:
    req = ToolCallRequest.model_validate(
        {"tool": "file.read", "session_id": "s1", "role": "administrator"}
    )
    call = ToolCall.from_request(req, user_id="u1", agent_id="a1", role=Role.VIEWER)
    assert call.role is Role.VIEWER
    assert call.user_id == "u1"


@pytest.mark.parametrize(
    "name",
    ["", "EmailSend", "email", "../etc/passwd", "email.send; rm -rf", "a." + "b" * 300],
)
def test_request_rejects_bad_tool_names(name: str) -> None:
    with pytest.raises(ValidationError):
        ToolCallRequest(tool=name, session_id="s1")


@pytest.mark.parametrize("name", ["email.send", "file.read", "db.query_rows"])
def test_request_accepts_good_tool_names(name: str) -> None:
    assert ToolCallRequest(tool=name, session_id="s1").tool == name


def test_tool_call_is_frozen() -> None:
    call = make_call()
    with pytest.raises(ValidationError):
        call.role = Role.ADMINISTRATOR  # type: ignore[misc]


def test_tool_call_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        make_call(allow=True)


# Decisions

def test_decision_default_deny_is_valid() -> None:
    d = make_decision()
    assert d.effect is Effect.BLOCK
    assert d.rule_hits == []


@pytest.mark.parametrize(
    ("effects", "expected", "code"),
    [
        ([Effect.ALLOW], Effect.ALLOW, ReasonCode.RULE_ALLOW),
        (
            [Effect.ALLOW, Effect.REQUIRE_APPROVAL],
            Effect.REQUIRE_APPROVAL,
            ReasonCode.RULE_APPROVAL,
        ),
        (
            [Effect.ALLOW, Effect.REQUIRE_APPROVAL, Effect.BLOCK],
            Effect.BLOCK,
            ReasonCode.RULE_BLOCK,
        ),
    ],
)
def test_decision_strongest_effect_wins(
    effects: list[Effect], expected: Effect, code: ReasonCode
) -> None:
    hits = [hit(e, f"rule-{i}") for i, e in enumerate(effects)]
    d = make_decision(effect=expected, reason_codes=[code], rule_hits=hits)
    assert d.effect is expected


@pytest.mark.parametrize(
    "overrides",
    [
        {"effect": Effect.ALLOW, "reason_codes": [ReasonCode.RULE_ALLOW]},
        {"reason_codes": []},
        {"risk_score": 1.5},
        {"main_reason": ""},
        {"policy_version": -1},
        {"allow": True},
        {
            "effect": Effect.ALLOW,
            "reason_codes": [ReasonCode.RULE_ALLOW],
            "rule_hits": [hit(Effect.BLOCK)],
        },
        {"reason_codes": [ReasonCode.RULE_ALLOW]},
        {"reason_codes": [ReasonCode.DEFAULT_DENY], "rule_hits": [hit(Effect.BLOCK)]},
    ],
)
def test_decision_rejects_inconsistent_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_decision(**overrides)


def test_block_helper() -> None:
    d = Decision.block("c1", ReasonCode.UNKNOWN_TOOL, "Tool is not registered.")
    assert d.effect is Effect.BLOCK
    assert d.reason_codes == [ReasonCode.UNKNOWN_TOOL]
    assert d.policy_version == 0


def test_block_helper_rejects_non_block_code() -> None:
    with pytest.raises(ValidationError):
        Decision.block("c1", ReasonCode.RULE_ALLOW, "Not a block code.")


def test_decision_json_round_trip() -> None:
    d = make_decision(
        effect=Effect.ALLOW,
        reason_codes=[ReasonCode.RULE_ALLOW],
        rule_hits=[hit(Effect.ALLOW)],
    )
    assert Decision.model_validate_json(d.model_dump_json()) == d


def test_reason_codes_match_policy_spec_doc() -> None:
    text = SPEC.read_text(encoding="utf-8")
    in_doc = set(re.findall(r"^\| `([A-Z][A-Z_]+)` \|", text, flags=re.MULTILINE))
    assert in_doc == {c.value for c in ReasonCode}
    for code in ReasonCode:
        assert isinstance(code.required_effect, Effect)


@pytest.mark.parametrize(
    ("effect", "code", "expected"),
    [
        (Effect.ALLOW, ReasonCode.RULE_ALLOW, True),
        (Effect.REQUIRE_APPROVAL, ReasonCode.RULE_APPROVAL, False),
        (Effect.BLOCK, ReasonCode.RULE_BLOCK, False),
    ],
)
def test_only_allow_is_executable(effect: Effect, code: ReasonCode, expected: bool) -> None:
    d = make_decision(effect=effect, reason_codes=[code], rule_hits=[hit(effect)])
    assert d.is_executable is expected


@pytest.mark.parametrize(
    "overrides",
    [{"rule_id": "Bad Id"}, {"priority": 1001}, {"reason": ""}],
)
def test_rule_hit_rejects_bad_values(overrides: dict[str, Any]) -> None:
    data: dict[str, Any] = {"rule_id": "r1", "effect": Effect.ALLOW, "reason": "Because."}
    data.update(overrides)
    with pytest.raises(ValidationError):
        RuleHit(**data)