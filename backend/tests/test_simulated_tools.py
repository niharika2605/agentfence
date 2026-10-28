"""Tests for the simulated tools and executor (Day 7)."""
import os
from typing import Any

import pytest

from agentfence.models import (
    Decision,
    Effect,
    ReasonCode,
    Role,
    RuleHit,
    ToolCall,
)
from agentfence.tools.simulated import (
    ExecutionRefused,
    SimulatedExecutor,
    SimulatedWorld,
    default_world,
)


def make_call(tool: str, arguments: dict[str, Any] | None = None) -> ToolCall:
    return ToolCall(
        session_id="s1",
        user_id="u1",
        agent_id="a1",
        role=Role.OPERATOR,
        tool=tool,
        arguments=arguments or {},
    )


def allow_for(call: ToolCall) -> Decision:
    return Decision(
        call_id=call.call_id,
        effect=Effect.ALLOW,
        reason_codes=[ReasonCode.RULE_ALLOW],
        rule_hits=[RuleHit(rule_id="r1", effect=Effect.ALLOW, reason="Test allow.")],
        main_reason="Test allow.",
        policy_version=1,
    )


def approval_for(call: ToolCall) -> Decision:
    return Decision(
        call_id=call.call_id,
        effect=Effect.REQUIRE_APPROVAL,
        reason_codes=[ReasonCode.RULE_APPROVAL],
        rule_hits=[RuleHit(rule_id="r2", effect=Effect.REQUIRE_APPROVAL, reason="Test.")],
        main_reason="Test approval.",
        policy_version=1,
    )


def run(
    executor: SimulatedExecutor, tool: str, arguments: dict[str, Any] | None = None
) -> Any:
    call = make_call(tool, arguments)
    return executor.execute(call, allow_for(call))


# ---------- default world ----------

def test_default_world_has_one_file_per_sensitivity_label() -> None:
    labels = {f.label.value for f in default_world().files.values()}
    assert {"public", "internal", "confidential", "secret"} <= labels


def test_default_world_has_an_injection_file_and_empty_outbox() -> None:
    world = default_world()
    note = world.files["/workspace/inbox/vendor_note.txt"]
    assert "attacker@evil.example" in note.content
    assert world.outbox == []
    assert world.code_runs == []


def test_each_executor_gets_its_own_world() -> None:
    first, second = SimulatedExecutor(), SimulatedExecutor()
    run(first, "email.send", {"to": "a@b.example", "subject": "s", "body": "b"})
    assert len(first.world.outbox) == 1
    assert second.world.outbox == []


# ---------- file.read ----------

def test_file_read_returns_content_and_label() -> None:
    result = run(SimulatedExecutor(), "file.read", {"path": "/workspace/finance/q3_report.txt"})
    assert result.ok
    assert "Q3 revenue" in result.output["content"]
    assert result.output["label"] == "confidential"


@pytest.mark.parametrize(
    "path",
    [
        "/workspace/missing.txt",
        "/workspace/public/../finance/q3_report.txt",
        "../../etc/passwd",
        "/WORKSPACE/PUBLIC/README.TXT",
    ],
)
def test_file_read_uses_exact_lookup_only(path: str) -> None:
    result = run(SimulatedExecutor(), "file.read", {"path": path})
    assert not result.ok
    assert result.error == "file not found"


@pytest.mark.parametrize("arguments", [{}, {"path": ""}, {"path": 5}, {"path": "x" * 501}])
def test_file_read_rejects_bad_arguments(arguments: dict[str, Any]) -> None:
    result = run(SimulatedExecutor(), "file.read", arguments)
    assert not result.ok


# ---------- email.send ----------

def test_email_send_records_the_email_in_the_outbox() -> None:
    executor = SimulatedExecutor()
    result = run(
        executor, "email.send", {"to": "me@company.example", "subject": "Hi", "body": "Text"}
    )
    assert result.ok
    assert result.output["message_number"] == 1
    sent = executor.world.outbox[0]
    assert (sent.to, sent.subject, sent.body) == ("me@company.example", "Hi", "Text")


@pytest.mark.parametrize(
    "arguments",
    [
        {"subject": "s", "body": "b"},
        {"to": "a@b.example", "body": "b"},
        {"to": "a@b.example", "subject": "s"},
        {"to": 7, "subject": "s", "body": "b"},
        {"to": "a@b.example", "subject": "s", "body": "x" * 10_001},
    ],
)
def test_email_send_with_bad_arguments_sends_nothing(arguments: dict[str, Any]) -> None:
    executor = SimulatedExecutor()
    result = run(executor, "email.send", arguments)
    assert not result.ok
    assert executor.world.outbox == []


# ---------- db.query ----------

def test_db_query_returns_all_rows_by_default() -> None:
    result = run(SimulatedExecutor(), "db.query", {"table": "customers"})
    assert result.ok
    assert len(result.output["rows"]) == 3
    assert result.output["label"] == "internal"


def test_db_query_filters_rows() -> None:
    result = run(
        SimulatedExecutor(), "db.query", {"table": "customers", "filters": {"plan": "pro"}}
    )
    assert [row["name"] for row in result.output["rows"]] == ["Ravi", "Meera"]


def test_db_query_limit_is_applied() -> None:
    result = run(SimulatedExecutor(), "db.query", {"table": "customers", "limit": 1})
    assert len(result.output["rows"]) == 1


def test_db_query_returns_copies_so_the_table_cannot_be_changed() -> None:
    executor = SimulatedExecutor()
    result = run(executor, "db.query", {"table": "customers", "limit": 1})
    result.output["rows"][0]["name"] = "Hacked"
    again = run(executor, "db.query", {"table": "customers", "limit": 1})
    assert again.output["rows"][0]["name"] == "Asha"


def test_db_query_labels_the_confidential_table() -> None:
    result = run(SimulatedExecutor(), "db.query", {"table": "salaries"})
    assert result.output["label"] == "confidential"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"table": "nope"},
        {"table": "customers", "limit": 0},
        {"table": "customers", "limit": 101},
        {"table": "customers", "limit": True},
        {"table": "customers", "limit": "5"},
        {"table": "customers", "filters": "plan=pro"},
        {"table": "customers", "filters": {"plan": True}},
        {"table": "customers", "filters": {"plan": ["pro"]}},
    ],
)
def test_db_query_rejects_bad_arguments(arguments: dict[str, Any]) -> None:
    assert not run(SimulatedExecutor(), "db.query", arguments).ok


# ---------- code.run ----------

def test_code_run_records_the_request_and_never_executes_it() -> None:
    executor = SimulatedExecutor()
    code = "__import__('os').environ['AGENTFENCE_PWNED'] = '1'"
    result = run(executor, "code.run", {"code": code})
    assert result.ok
    assert result.output["stdout"] == "[simulated] code was not executed"
    assert "AGENTFENCE_PWNED" not in os.environ
    assert executor.world.code_runs == [code]


def test_code_run_needs_code() -> None:
    assert not run(SimulatedExecutor(), "code.run", {}).ok


# ---------- executor guard (a second line of defense for invariant I1) ----------

def test_executor_refuses_a_block_decision() -> None:
    executor = SimulatedExecutor()
    call = make_call("email.send", {"to": "a@b.example", "subject": "s", "body": "b"})
    blocked = Decision.block(call.call_id, ReasonCode.DEFAULT_DENY, "No rule matched.")
    with pytest.raises(ExecutionRefused):
        executor.execute(call, blocked)
    assert executor.executed == []
    assert executor.world.outbox == []


def test_executor_refuses_a_decision_that_needs_approval() -> None:
    executor = SimulatedExecutor()
    call = make_call("code.run", {"code": "print(1)"})
    with pytest.raises(ExecutionRefused):
        executor.execute(call, approval_for(call))
    assert executor.executed == []
    assert executor.world.code_runs == []


def test_executor_refuses_a_decision_for_another_call() -> None:
    executor = SimulatedExecutor()
    call = make_call("file.read", {"path": "/workspace/public/readme.txt"})
    other = make_call("file.read", {"path": "/workspace/public/readme.txt"})
    with pytest.raises(ExecutionRefused):
        executor.execute(call, allow_for(other))
    assert executor.executed == []


def test_executor_records_allowed_calls() -> None:
    executor = SimulatedExecutor()
    call = make_call("file.read", {"path": "/workspace/public/readme.txt"})
    executor.execute(call, allow_for(call))
    assert [(r.call_id, r.tool) for r in executor.executed] == [(call.call_id, "file.read")]


def test_executor_record_keeps_a_copy_of_the_arguments() -> None:
    executor = SimulatedExecutor()
    arguments = {"path": "/workspace/public/readme.txt"}
    call = make_call("file.read", arguments)
    executor.execute(call, allow_for(call))
    arguments["path"] = "changed"
    call.arguments["path"] = "changed"
    assert executor.executed[0].arguments["path"] == "/workspace/public/readme.txt"


def test_unknown_tool_returns_an_error_result() -> None:
    result = run(SimulatedExecutor(), "shell.run", {"cmd": "ls"})
    assert not result.ok
    assert result.error == "unknown simulated tool"


def test_all_tool_output_is_marked_untrusted() -> None:
    executor = SimulatedExecutor()
    ok = run(executor, "file.read", {"path": "/workspace/public/readme.txt"})
    failed = run(executor, "file.read", {"path": "/nope"})
    assert ok.untrusted is True
    assert failed.untrusted is True


def test_a_world_can_be_supplied_and_inspected() -> None:
    world = SimulatedWorld()
    executor = SimulatedExecutor(world)
    run(executor, "email.send", {"to": "a@b.example", "subject": "s", "body": "b"})
    assert len(world.outbox) == 1