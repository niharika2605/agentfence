"""Tests for the policy loader (Day 14)."""
from pathlib import Path

import pytest

from agentfence.policy.loader import (
    MAX_POLICY_BYTES,
    MAX_PROBLEMS,
    PolicyError,
    load_policy_file,
    load_policy_text,
)
from agentfence.policy.schema import Policy

EXAMPLES = Path(__file__).resolve().parents[1] / "policies" / "examples"

RULE = """
  - id: r1
    effect: allow
    tool: file.read
    reason: Test rule.
"""


def policy_text(body: str = RULE, head: str = "schema: 1\nname: test\n") -> str:
    return f"{head}rules:{body}"


def problems_of(text: object) -> list[str]:
    with pytest.raises(PolicyError) as caught:
        load_policy_text(text)
    return caught.value.problems


def has_problem(text: object, fragment: str) -> bool:
    return any(fragment in problem for problem in problems_of(text))


# ---------- the example files ----------

@pytest.mark.parametrize("name", ["basic_valid.yaml", "viewer_readonly_valid.yaml"])
def test_valid_examples_load(name: str) -> None:
    policy = load_policy_file(EXAMPLES / name)
    assert isinstance(policy, Policy)
    assert policy.schema_version == 1
    assert policy.rules


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("invalid_unknown_effect.yaml", "rules.0.effect"),
        ("invalid_duplicate_id.yaml", "duplicate rule id 'same-id'"),
        ("invalid_unknown_list.yaml", "unknown list 'nowhere'"),
    ],
)
def test_invalid_examples_fail_with_a_clear_message(name: str, fragment: str) -> None:
    with pytest.raises(PolicyError) as caught:
        load_policy_file(EXAMPLES / name)
    assert any(fragment in problem for problem in caught.value.problems)


def test_basic_example_has_the_expected_shape() -> None:
    policy = load_policy_file(EXAMPLES / "basic_valid.yaml")
    assert [rule.id for rule in policy.rules][0] == "allow-read-public-and-internal-files"
    assert policy.lists == {"allowed_domains": ["company.com"]}
    assert policy.rules[3].priority == 150
    assert policy.rules[0].roles is not None and len(policy.rules[0].roles) == 3
    assert policy.rules[1].roles is None
    assert policy.rules[0].when[0].field == "resource.label"


def test_minimal_policy_loads_with_defaults() -> None:
    policy = load_policy_text(policy_text())
    rule = policy.rules[0]
    assert rule.priority == 100
    assert rule.roles is None
    assert rule.when == []
    assert rule.tools == ("file.read",)
    assert policy.lists == {}


def test_a_list_of_tools_is_accepted() -> None:
    text = policy_text(RULE.replace("tool: file.read", "tool: [file.read, db.query]"))
    assert load_policy_text(text).rules[0].tools == ("file.read", "db.query")


# ---------- yaml safety ----------

def test_duplicate_keys_are_an_error_at_every_level() -> None:
    assert has_problem("schema: 1\nschema: 1\nname: t\nrules:" + RULE, "duplicate key")
    twice = RULE.replace("effect: allow", "effect: allow\n    effect: block")
    assert has_problem(policy_text(twice), "duplicate key")
    cond = """
  - id: r1
    effect: allow
    tool: file.read
    reason: Test rule.
    when:
      - field: resource.label
        field: resource.label
        op: eq
        value: public
"""
    assert has_problem(policy_text(cond), "duplicate key")


def test_anchors_and_aliases_are_not_allowed() -> None:
    text = "schema: 1\nname: t\nx: &a 1\nrules:" + RULE
    assert has_problem(text, "anchors and aliases")
    text = (
        "schema: 1\nname: t\nrules:\n  - &r\n"
        "    id: r1\n    effect: allow\n    tool: file.read\n    reason: x\n"
    )
    assert has_problem(text, "anchors and aliases")


def test_python_tags_are_refused() -> None:
    text = "schema: 1\nname: !!python/object/apply:os.getcwd []\nrules:" + RULE
    assert has_problem(text, "YAML error")


@pytest.mark.parametrize(
    "text",
    ["", "   ", "- a\n- b\n", "just text", "42", "null", "schema: 1\n---\nschema: 1\n"],
)
def test_documents_that_are_not_one_mapping_are_refused(text: str) -> None:
    assert problems_of(text)


def test_broken_yaml_reports_a_line() -> None:
    assert has_problem("schema: 1\nname: [unclosed\nrules:", "line")


def test_non_text_input_is_refused() -> None:
    assert problems_of(None) == ["policy must be text"]
    assert problems_of(b"schema: 1") == ["policy must be text"]


def test_size_limit() -> None:
    big = "# " + "x" * MAX_POLICY_BYTES + "\n" + policy_text()
    assert problems_of(big) == ["policy file is too large"]


def test_file_size_limit(tmp_path: Path) -> None:
    file = tmp_path / "big.yaml"
    file.write_text("# " + "x" * MAX_POLICY_BYTES + "\n" + policy_text(), encoding="utf-8")
    with pytest.raises(PolicyError, match="too large"):
        load_policy_file(file)


def test_load_from_a_file(tmp_path: Path) -> None:
    file = tmp_path / "p.yaml"
    file.write_text(policy_text(), encoding="utf-8")
    assert load_policy_file(file).name == "test"


# ---------- structure ----------

@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("schema: 2\nname: t\nrules:" + RULE, "schema must be 1"),
        ('schema: "1"\nname: t\nrules:' + RULE, "schema"),
        ("schema: true\nname: t\nrules:" + RULE, "schema"),
        ("name: t\nrules:" + RULE, "schema"),
        ("schema: 1\nrules:" + RULE, "name"),
        ("schema: 1\nname: Bad Name\nrules:" + RULE, "name"),
        ("schema: 1\nname: t\n", "rules"),
        ("schema: 1\nname: t\nrules: []\n", "rules"),
        ("schema: 1\nname: t\nrules:" + RULE + "extra: 1\n", "extra"),
        ("schema: 1\nname: t\nowner: me\nrules:" + RULE, "owner"),
    ],
)
def test_top_level_problems(text: str, fragment: str) -> None:
    assert has_problem(text, fragment)


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ("id: r1", "id: R1", "id"),
        ("id: r1", "id: 5", "id"),
        ("id: r1", "id: '-r1'", "id"),
        ("effect: allow", "effect: ALLOW", "effect"),
        ("effect: allow", "effect: permit", "effect"),
        ("effect: allow", "effect: 1", "effect"),
        ("tool: file.read", "tool: 5", "tool"),
        ("tool: file.read", "tool: []", "tool list is empty"),
        ("tool: file.read", "tool: File.read", "bad tool pattern"),
        ("tool: file.read", "tool: file.", "bad tool pattern"),
        ("tool: file.read", "tool: 'file.*.x'", "bad tool pattern"),
        ("tool: file.read", "tool: file", "bad tool pattern"),
        ("reason: Test rule.", "reason: ''", "reason"),
        ("reason: Test rule.", "reason: 5", "reason"),
        ("reason: Test rule.", "reason: yes", "reason"),
        ("reason: Test rule.", "reason: Test rule.\n    priority: '100'", "priority"),
        ("reason: Test rule.", "reason: Test rule.\n    priority: 1001", "priority"),
        ("reason: Test rule.", "reason: Test rule.\n    priority: -1", "priority"),
        ("reason: Test rule.", "reason: Test rule.\n    priority: true", "priority"),
        ("reason: Test rule.", "reason: Test rule.\n    roles: viewer", "roles"),
        ("reason: Test rule.", "reason: Test rule.\n    roles: [root]", "roles"),
        ("reason: Test rule.", "reason: Test rule.\n    roles: []", "roles list is empty"),
        ("reason: Test rule.", "reason: Test rule.\n    roles: [viewer, viewer]", "repeats"),
        ("reason: Test rule.", "reason: Test rule.\n    mode: fast", "mode"),
        ("reason: Test rule.", "reason: Test rule.\n    when: x", "when"),
    ],
)
def test_rule_problems(old: str, new: str, fragment: str) -> None:
    text = policy_text(RULE.replace(old, new))
    assert has_problem(text, fragment), problems_of(text)


def test_a_rule_without_a_reason_is_refused() -> None:
    text = policy_text(RULE.replace("    reason: Test rule.\n", ""))
    assert has_problem(text, "reason")


def test_unquoted_yes_and_no_are_not_silently_turned_into_booleans() -> None:
    text = policy_text(
        """
  - id: r1
    effect: allow
    tool: file.read
    reason: Test rule.
    when:
      - field: user.id
        op: eq
        value: no
"""
    )
    assert has_problem(text, "does not fit field")


def test_unquoted_dates_are_not_accepted_as_text() -> None:
    text = policy_text(
        """
  - id: r1
    effect: allow
    tool: file.read
    reason: Test rule.
    when:
      - field: user.id
        op: eq
        value: 2024-01-01
"""
    )
    assert problems_of(text)


def test_many_problems_are_cut_to_a_limit() -> None:
    rules = "".join(
        f"\n  - id: r{i}\n    effect: nope\n    tool: file.read\n    reason: x" for i in range(80)
    )
    assert len(problems_of(policy_text(rules))) <= MAX_PROBLEMS


def test_all_problems_are_reported_together() -> None:
    body = """
  - id: r1
    effect: allow
    tool: file.read
    reason: x
    when:
      - field: nope.field
        op: eq
        value: a
      - field: resource.label
        op: gt
        value: bogus
  - id: r1
    effect: allow
    tool: file.read
    reason: x
"""
    found = problems_of(policy_text(body))
    assert len(found) >= 3
    assert any("unknown field" in p for p in found)
    assert any("does not fit" in p for p in found)
    assert any("duplicate rule id" in p for p in found)