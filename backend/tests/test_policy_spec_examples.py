"""Checks the example policy files against the policy spec (docs/policy_spec.md).

This is a small temporary checker. Day 14 replaces it with the real schema.
"""
from pathlib import Path
from typing import Any

import pytest
import yaml

BACKEND = Path(__file__).resolve().parents[1]
EXAMPLES = BACKEND / "policies" / "examples"
DOCS = Path(__file__).resolve().parents[2] / "docs"

TOP_KEYS = {"schema", "name", "lists", "rules"}
RULE_KEYS = {"id", "effect", "tool", "roles", "priority", "when", "reason"}
REQUIRED_RULE_KEYS = ("id", "effect", "tool", "reason")
EFFECTS = {"allow", "require_approval", "block"}
OPS = {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"}

VALID_FILES = ["basic_valid.yaml", "viewer_readonly_valid.yaml"]
INVALID_FILES = [
    ("invalid_unknown_effect.yaml", "bad effect"),
    ("invalid_duplicate_id.yaml", "duplicate rule id"),
    ("invalid_unknown_list.yaml", "unknown list"),
]


def load(name: str) -> Any:
    return yaml.safe_load((EXAMPLES / name).read_text(encoding="utf-8"))


def condition_problems(cond: Any, list_names: set[str]) -> list[str]:
    if not isinstance(cond, dict):
        return ["each condition must be a mapping"]
    found: list[str] = []
    if "field" not in cond:
        found.append("condition missing field")
    if cond.get("op") not in OPS:
        found.append(f"bad op: {cond.get('op')}")
    has_value = "value" in cond
    has_list = "list" in cond
    if has_value == has_list:
        found.append("condition needs exactly one of value or list")
    if has_list and cond["list"] not in list_names:
        found.append(f"unknown list: {cond['list']}")
    return found


def rule_problems(rule: Any, list_names: set[str], seen_ids: set[str]) -> list[str]:
    if not isinstance(rule, dict):
        return ["each rule must be a mapping"]
    found: list[str] = []
    for key in rule:
        if key not in RULE_KEYS:
            found.append(f"unknown rule key: {key}")
    for key in REQUIRED_RULE_KEYS:
        if key not in rule:
            found.append(f"missing required key: {key}")
    rule_id = rule.get("id")
    if isinstance(rule_id, str):
        if rule_id in seen_ids:
            found.append(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)
    if rule.get("effect") not in EFFECTS:
        found.append(f"bad effect in rule {rule_id}")
    for cond in rule.get("when", []):
        found.extend(condition_problems(cond, list_names))
    return found


def problems(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return ["policy must be a mapping"]
    found: list[str] = []
    for key in doc:
        if key not in TOP_KEYS:
            found.append(f"unknown top level key: {key}")
    if doc.get("schema") != 1:
        found.append("schema must be 1")
    if not isinstance(doc.get("name"), str):
        found.append("name must be a string")
    lists = doc.get("lists", {})
    list_names = set(lists) if isinstance(lists, dict) else set()
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        found.append("rules must be a non empty list")
        return found
    seen_ids: set[str] = set()
    for rule in rules:
        found.extend(rule_problems(rule, list_names, seen_ids))
    return found


@pytest.mark.parametrize("name", VALID_FILES)
def test_valid_examples_have_no_problems(name: str) -> None:
    assert problems(load(name)) == []


@pytest.mark.parametrize(("name", "expected"), INVALID_FILES)
def test_invalid_examples_are_rejected(name: str, expected: str) -> None:
    found = problems(load(name))
    assert any(expected in p for p in found), found


def test_policy_spec_doc_states_core_rules() -> None:
    text = (DOCS / "policy_spec.md").read_text(encoding="utf-8").lower()
    for phrase in ("default deny", "deny overrides allow", "priority"):
        assert phrase in text
        