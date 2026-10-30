"""Tests for the canonicalization chain (Day 12)."""
from typing import Any

import pytest
from pydantic import BaseModel, Field

from agentfence.canon.arguments import (
    DEFAULT_LOCATORS,
    CanonConfig,
    CanonicalArguments,
    Locator,
    canonicalize_call,
    canonicalize_name,
)
from agentfence.canon.errors import CanonicalizationError
from agentfence.models import Decision, Effect, ReasonCode, Role, RuleHit, ToolCall
from agentfence.tools.registry import (
    STRICT_ARGS,
    ToolRegistry,
    ToolRisk,
    ToolSpec,
    default_registry,
)
from agentfence.tools.simulated import SimulatedExecutor


class FetchArgs(BaseModel):
    model_config = STRICT_ARGS
    url: str = Field(min_length=1, max_length=2000)
    referrer: str | None = None


def fetch_registry() -> ToolRegistry:
    registry = default_registry()
    registry.register(ToolSpec("http.get", "Fetch a URL.", FetchArgs, ToolRisk.MEDIUM))
    return registry


FETCH_LOCATORS = {
    **DEFAULT_LOCATORS,
    "http.get": {"url": Locator.URL, "referrer": Locator.URL},
}


def run(tool: str, arguments: dict[str, Any], **kwargs: Any) -> CanonicalArguments | Decision:
    return canonicalize_call(default_registry(), "c1", tool, arguments, **kwargs)


def ok(tool: str, arguments: dict[str, Any], **kwargs: Any) -> CanonicalArguments:
    result = run(tool, arguments, **kwargs)
    assert isinstance(result, CanonicalArguments), result
    return result


# ---------- the rules table ----------

def test_every_registered_tool_has_canonicalization_rules() -> None:
    assert set(DEFAULT_LOCATORS) == default_registry().names()


def test_every_rule_points_at_a_real_argument() -> None:
    registry = default_registry()
    for tool, rules in DEFAULT_LOCATORS.items():
        spec = registry.get(tool)
        assert spec is not None
        for name in rules:
            assert name in spec.args_model.model_fields, f"{tool}.{name}"


def test_a_tool_without_rules_fails_closed() -> None:
    result = run("file.read", {"path": "/workspace/public/readme.txt"}, locators={})
    assert isinstance(result, Decision)
    assert result.reason_codes == [ReasonCode.CANONICALIZATION_FAILED]
    assert "no canonicalization rules" in result.main_reason


# ---------- results ----------

def test_clean_call_has_no_encoded_fields() -> None:
    result = ok("file.read", {"path": "/workspace/public/readme.txt"})
    assert result.arguments == {"path": "/workspace/public/readme.txt"}
    assert result.encoded == {}
    assert not result.was_encoded
    assert result.spec.name == "file.read"


def test_encoded_fields_are_reported_with_their_layers() -> None:
    result = ok("file.read", {"path": "/workspace/public/%252e%252e/notes/meeting.txt"})
    assert result.arguments["path"] == "/workspace/notes/meeting.txt"
    assert result.encoded == {"path": ("url", "url")}
    assert result.was_encoded


def test_defaults_from_the_schema_are_kept() -> None:
    result = ok("db.query", {"table": "customers"})
    assert result.arguments == {"table": "customers", "filters": {}, "limit": 10}


def test_validation_decisions_pass_through_unchanged() -> None:
    result = run("shell.run", {})
    assert isinstance(result, Decision)
    assert result.reason_codes == [ReasonCode.UNKNOWN_TOOL]


def test_canonicalization_failure_names_the_field_but_not_the_value() -> None:
    result = run("file.read", {"path": "/workspace/%2e%2e/%2e%2e/secret-token-123"})
    assert isinstance(result, Decision)
    assert result.reason_codes == [ReasonCode.CANONICALIZATION_FAILED]
    assert "'path'" in result.main_reason
    assert "secret-token-123" not in result.main_reason


# ---------- configuration ----------

def test_narrow_roots_deny_paths_outside_them() -> None:
    config = CanonConfig(allowed_roots=("/workspace/public",))
    assert ok("file.read", {"path": "/workspace/public/readme.txt"}, config=config)
    result = run("file.read", {"path": "/workspace/keys/api_keys.txt"}, config=config)
    assert isinstance(result, Decision)


def test_fold_case_config_lowercases_paths() -> None:
    config = CanonConfig(fold_case=True)
    result = ok("file.read", {"path": "/WORKSPACE/Public/README.TXT"}, config=config)
    assert result.arguments["path"] == "/workspace/public/readme.txt"


def test_symlinks_come_from_the_config() -> None:
    links = {"/workspace/public/latest": "/workspace/public/readme.txt"}
    config = CanonConfig(symlinks=links)
    result = ok("file.read", {"path": "/workspace/public/latest"}, config=config)
    assert result.arguments["path"] == "/workspace/public/readme.txt"
    without_links = ok("file.read", {"path": "/workspace/public/latest"})
    assert without_links.arguments["path"] == "/workspace/public/latest"


# ---------- optional fields and other locator kinds ----------

def test_an_optional_location_field_may_be_missing_or_none() -> None:
    registry = fetch_registry()
    given = [{"url": "https://example.com/"}, {"url": "https://example.com/", "referrer": None}]
    for arguments in given:
        result = canonicalize_call(registry, "c1", "http.get", arguments, locators=FETCH_LOCATORS)
        assert isinstance(result, CanonicalArguments)
        assert result.arguments["url"] == "https://example.com/"


def test_a_given_optional_location_field_is_checked() -> None:
    registry = fetch_registry()
    arguments = {"url": "https://example.com/", "referrer": "https://user@evil.example/"}
    result = canonicalize_call(registry, "c1", "http.get", arguments, locators=FETCH_LOCATORS)
    assert isinstance(result, Decision)
    assert "'referrer'" in result.main_reason


@pytest.mark.parametrize("name", ["customers", "reports_table", "a1_b2"])
def test_good_names(name: str) -> None:
    assert canonicalize_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "Customers", "1table", "a-b", "a b", "a;b", "../a", "a" * 65, "caf\u00e9"]
)
def test_bad_names(name: str) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_name(name)


# ---------- idempotence and the executor ----------

def test_canonical_arguments_are_a_fixed_point() -> None:
    first = ok("file.read", {"path": "/workspace/public/%2e%2e/notes/meeting.txt"})
    second = ok("file.read", first.arguments)
    assert second.arguments == first.arguments
    assert second.encoded == {}


def test_canonical_arguments_run_in_the_executor() -> None:
    canonical = ok("file.read", {"path": "/workspace/public/%2e%2e/public/readme.txt"})
    call = ToolCall(
        session_id="s1",
        user_id="u1",
        agent_id="a1",
        role=Role.OPERATOR,
        tool=canonical.tool,
        arguments=canonical.arguments,
    )
    decision = Decision(
        call_id=call.call_id,
        effect=Effect.ALLOW,
        reason_codes=[ReasonCode.RULE_ALLOW],
        rule_hits=[RuleHit(rule_id="r1", effect=Effect.ALLOW, reason="Test.")],
        main_reason="Test.",
        policy_version=1,
    )
    result = SimulatedExecutor().execute(call, decision)
    assert result.ok
    assert "Welcome" in result.output["content"]