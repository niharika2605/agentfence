"""Tests for the identity step of the pipeline (Day 13)."""
from typing import Any

import pytest

from agentfence.identity import roles
from agentfence.identity.gate import authorize_call
from agentfence.identity.tokens import TokenService
from agentfence.models import Decision, Effect, ReasonCode, Role, ToolCall, ToolCallRequest

KEY = b"k" * 32


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000

    def __call__(self) -> int:
        return self.now


def request(tool: str = "file.read", **extra: Any) -> ToolCallRequest:
    data: dict[str, Any] = {
        "tool": tool,
        "arguments": {"path": "/workspace/public/readme.txt"},
        "session_id": "sess-1",
    }
    data.update(extra)
    return ToolCallRequest.model_validate(data)


def token_for(
    service: TokenService, role: Role = Role.OPERATOR, scope: list[str] | None = None
) -> str:
    return service.issue(
        user_id="user-1",
        agent_id="agent-1",
        session_id="sess-1",
        role=role,
        scope=scope or ["file.read", "email.send"],
    )


def blocked(result: ToolCall | Decision, code: ReasonCode) -> Decision:
    assert isinstance(result, Decision), result
    assert result.effect is Effect.BLOCK
    assert result.reason_codes == [code]
    assert not result.is_executable
    assert result.call_id
    return result


# ---------- the good path ----------

def test_a_good_token_gives_a_tool_call_with_identity_from_the_token() -> None:
    service = TokenService(KEY)
    result = authorize_call(service, token_for(service), request())
    assert isinstance(result, ToolCall)
    assert (result.user_id, result.agent_id, result.session_id) == ("user-1", "agent-1", "sess-1")
    assert result.role is Role.OPERATOR
    assert result.tool == "file.read"
    assert result.arguments == {"path": "/workspace/public/readme.txt"}


def test_each_call_gets_its_own_call_id() -> None:
    service = TokenService(KEY)
    token = token_for(service)
    first = authorize_call(service, token, request())
    second = authorize_call(service, token, request())
    assert isinstance(first, ToolCall) and isinstance(second, ToolCall)
    assert first.call_id != second.call_id


# ---------- invariant I7: the client cannot choose who it is ----------

def test_fields_in_the_request_cannot_change_identity_or_role() -> None:
    service = TokenService(KEY)
    token = token_for(service, role=Role.VIEWER, scope=["file.read"])
    sneaky = request(
        role="administrator",
        user_id="someone-else",
        agent_id="other-agent",
        allow=True,
        approved=True,
    )
    result = authorize_call(service, token, sneaky)
    assert isinstance(result, ToolCall)
    assert result.role is Role.VIEWER
    assert result.user_id == "user-1"
    assert result.agent_id == "agent-1"


# ---------- bad identity ----------

@pytest.mark.parametrize("token", [None, 5, "", "garbage", "af1.a.b", b"bytes"])
def test_garbage_tokens_are_blocked(token: object) -> None:
    blocked(authorize_call(TokenService(KEY), token, request()), ReasonCode.IDENTITY_INVALID)


def test_all_identity_failures_look_the_same_to_the_agent() -> None:
    clock = Clock()
    service = TokenService(KEY, clock=clock)
    other_service = TokenService(b"z" * 32, clock=clock)
    good = token_for(service)

    expired = token_for(service)
    revoked = token_for(service)
    service.revoke(service.verify(revoked).token_id)
    clock.now += 10_000

    reasons = {
        blocked(authorize_call(service, bad, request()), ReasonCode.IDENTITY_INVALID).main_reason
        for bad in [expired, revoked, token_for(other_service), "junk", good[:-3] + "abc"]
    }
    assert reasons == {"identity could not be verified"}


def test_a_token_for_another_session_is_blocked() -> None:
    service = TokenService(KEY)
    token = token_for(service)
    blocked(
        authorize_call(service, token, request(session_id="sess-2")),
        ReasonCode.IDENTITY_INVALID,
    )


def test_a_revoked_token_is_blocked() -> None:
    service = TokenService(KEY)
    token = token_for(service)
    service.revoke(service.verify(token).token_id)
    blocked(authorize_call(service, token, request()), ReasonCode.IDENTITY_INVALID)


# ---------- scope and role ----------

def test_a_tool_outside_the_scope_is_blocked() -> None:
    service = TokenService(KEY)
    result = authorize_call(service, token_for(service, scope=["file.read"]), request("email.send"))
    decision = blocked(result, ReasonCode.ROLE_DENIED)
    assert decision.main_reason == "tool is outside the scope of this session"


def test_a_tool_in_scope_but_not_allowed_for_the_role_is_blocked() -> None:
    service = TokenService(KEY)
    token = token_for(service, scope=["file.*"])
    result = authorize_call(service, token, request("file.delete"))
    decision = blocked(result, ReasonCode.ROLE_DENIED)
    assert decision.main_reason == "role is not allowed to use this tool"


def test_role_changes_apply_to_tokens_that_were_already_issued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = TokenService(KEY)
    token = token_for(service, role=Role.VIEWER, scope=["file.read"])
    assert isinstance(authorize_call(service, token, request()), ToolCall)
    monkeypatch.setitem(roles.ROLE_PERMISSIONS, Role.VIEWER, {})
    blocked(authorize_call(service, token, request()), ReasonCode.ROLE_DENIED)


def test_unknown_tool_names_are_blocked_for_every_role() -> None:
    service = TokenService(KEY)
    for role in Role:
        token = token_for(service, role=role, scope=["file.read"])
        blocked(authorize_call(service, token, request("shell.run")), ReasonCode.ROLE_DENIED)