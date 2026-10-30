"""The canonicalization attack suite (Day 12).

Runs every entry in tests/attacks/canonicalization.yaml through the whole chain:
schema check, decode, canonicalize. It also proves that a blocked call never
reaches the executor, and that normal calls still work.
"""
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel, Field

from agentfence.canon.arguments import (
    DEFAULT_LOCATORS,
    CanonConfig,
    CanonicalArguments,
    Locator,
    canonicalize_call,
)
from agentfence.models import Decision, Effect, ReasonCode, Role, RuleHit, ToolCall
from agentfence.tools.registry import (
    STRICT_ARGS,
    ToolRegistry,
    ToolRisk,
    ToolSpec,
    default_registry,
)
from agentfence.tools.simulated import SimulatedExecutor

CORPUS_FILE = Path(__file__).resolve().parent / "attacks" / "canonicalization.yaml"
CORPUS: list[dict[str, Any]] = yaml.safe_load(CORPUS_FILE.read_text(encoding="utf-8"))

CONFIG = CanonConfig(
    symlinks={
        "/workspace/public/latest": "/workspace/public/readme.txt",
        "/workspace/public/shortcut": "/workspace/keys/api_keys.txt",
        "/workspace/public/escape": "/etc",
        "/workspace/loop/a": "/workspace/loop/b",
        "/workspace/loop/b": "/workspace/loop/a",
    }
)
LOCATORS = {**DEFAULT_LOCATORS, "http.get": {"url": Locator.URL}}


class FetchArgs(BaseModel):
    model_config = STRICT_ARGS
    url: str = Field(min_length=1, max_length=2000)


def build_registry() -> ToolRegistry:
    registry = default_registry()
    registry.register(ToolSpec("http.get", "Fetch a URL.", FetchArgs, ToolRisk.MEDIUM))
    return registry


def run_entry(entry: dict[str, Any]) -> CanonicalArguments | Decision:
    return canonicalize_call(
        build_registry(), "c1", entry["tool"], entry["args"], config=CONFIG, locators=LOCATORS
    )


def entries(kind: str) -> list[dict[str, Any]]:
    return [e for e in CORPUS if e["expect"] == kind]


def ids(items: list[dict[str, Any]]) -> list[str]:
    return [e["id"] for e in items]


def allow_for(call: ToolCall) -> Decision:
    return Decision(
        call_id=call.call_id,
        effect=Effect.ALLOW,
        reason_codes=[ReasonCode.RULE_ALLOW],
        rule_hits=[RuleHit(rule_id="r1", effect=Effect.ALLOW, reason="Test.")],
        main_reason="Test.",
        policy_version=1,
    )


# ---------- the corpus itself ----------

def test_corpus_ids_are_unique_and_entries_are_well_formed() -> None:
    assert len({e["id"] for e in CORPUS}) == len(CORPUS)
    for entry in CORPUS:
        assert entry["expect"] in ("ok", "block"), entry["id"]
        assert {"id", "tool", "args", "expect"} <= set(entry), entry["id"]
        if entry["expect"] == "ok":
            assert "canonical" in entry, entry["id"]


def test_corpus_covers_every_family() -> None:
    families = {e["id"].split("-")[0] for e in CORPUS}
    assert {"path", "email", "table", "url", "code", "call"} <= families
    assert len(CORPUS) >= 100


def test_corpus_is_not_only_blocks() -> None:
    assert len(entries("ok")) >= 30
    assert len(entries("block")) >= 70


# ---------- every attack is blocked, every normal call passes ----------

@pytest.mark.parametrize("entry", entries("block"), ids=ids(entries("block")))
def test_attack_is_blocked(entry: dict[str, Any]) -> None:
    result = run_entry(entry)
    assert isinstance(result, Decision), result
    assert result.effect is Effect.BLOCK
    expected_code = ReasonCode(entry.get("code", "CANONICALIZATION_FAILED"))
    assert result.reason_codes == [expected_code]
    for value in entry["args"].values():
        if isinstance(value, str) and len(value) >= 6:
            assert value not in result.main_reason


@pytest.mark.parametrize("entry", entries("ok"), ids=ids(entries("ok")))
def test_normal_call_comes_out_canonical(entry: dict[str, Any]) -> None:
    result = run_entry(entry)
    assert isinstance(result, CanonicalArguments), result
    for key, expected in entry["canonical"].items():
        assert result.arguments[key] == expected
    wanted = {name: tuple(layers) for name, layers in entry.get("layers", {}).items()}
    assert result.encoded == wanted


@pytest.mark.parametrize("entry", entries("ok"), ids=ids(entries("ok")))
def test_canonical_output_is_stable(entry: dict[str, Any]) -> None:
    first = run_entry(entry)
    assert isinstance(first, CanonicalArguments)
    again = canonicalize_call(
        build_registry(), "c1", entry["tool"], first.arguments, config=CONFIG, locators=LOCATORS
    )
    assert isinstance(again, CanonicalArguments)
    assert again.arguments == first.arguments
    assert again.encoded == {}


# ---------- a blocked call never reaches the executor ----------

def test_only_passed_calls_reach_the_executor_and_the_world_is_clean_of_attacks() -> None:
    executor = SimulatedExecutor()
    reached: list[str] = []
    expected_emails: list[str] = []
    for entry in CORPUS:
        result = run_entry(entry)
        if isinstance(result, Decision):
            continue
        if entry["tool"] == "http.get":
            continue
        call = ToolCall(
            session_id="s1",
            user_id="u1",
            agent_id="a1",
            role=Role.OPERATOR,
            tool=result.tool,
            arguments=result.arguments,
        )
        executor.execute(call, allow_for(call))
        reached.append(entry["id"])
        if entry["tool"] == "email.send":
            expected_emails.append(result.arguments["to"])

    runnable_ok = [e["id"] for e in entries("ok") if e["tool"] != "http.get"]
    assert reached == runnable_ok
    assert len(executor.executed) == len(runnable_ok)
    assert [mail.to for mail in executor.world.outbox] == expected_emails
    blocked_recipients = [
        e["args"]["to"] for e in entries("block") if e["tool"] == "email.send"
    ]
    assert not set(blocked_recipients) & {mail.to for mail in executor.world.outbox}
    assert all("etc/passwd" not in code for code in executor.world.code_runs)