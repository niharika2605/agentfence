"""Tests for the policy linter (Day 14)."""
import re
from pathlib import Path

import pytest

from agentfence.policy.linter import LINT_CODES, LintFinding, has_errors, lint_policy
from agentfence.policy.loader import load_policy_file, load_policy_text
from agentfence.policy.schema import Policy
from agentfence.tools.registry import default_registry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "backend" / "policies" / "examples"
SPEC = ROOT / "docs" / "policy_spec.md"


def rule(
    rule_id: str,
    effect: str,
    tool: str = "file.read",
    roles: str = "",
    when: str = "",
) -> str:
    text = f"  - id: {rule_id}\n    effect: {effect}\n    tool: '{tool}'\n    reason: Test.\n"
    if roles:
        text += f"    roles: [{roles}]\n"
    if when:
        text += "    when:\n" + "".join(f"      - {line}\n" for line in when.split(" ;; "))
    return text


def make(*rules: str, lists: str = "") -> Policy:
    return load_policy_text(f"schema: 1\nname: test\n{lists}rules:\n" + "".join(rules))


def codes(policy: Policy, registry: bool = True) -> list[str]:
    found = lint_policy(policy, registry=default_registry() if registry else None)
    return [finding.code for finding in found]


LABEL_PUBLIC = "{field: resource.label, op: eq, value: public}"
LABEL_TOP = "{field: resource.label, op: eq, value: secret}"
UNTRUSTED = "{field: session.untrusted_content, op: eq, value: true}"


# ---------- the examples and the doc ----------

@pytest.mark.parametrize("name", ["basic_valid.yaml", "viewer_readonly_valid.yaml"])
def test_example_policies_are_clean(name: str) -> None:
    policy = load_policy_file(EXAMPLES / name)
    assert lint_policy(policy, registry=default_registry()) == []


def test_lint_codes_in_the_doc_match_the_code() -> None:
    text = SPEC.read_text(encoding="utf-8")
    rows = re.findall(r"^\| (L\d{3}) \| (error|warning) \|", text, flags=re.MULTILINE)
    assert dict(rows) == {code: severity for code, (severity, _) in LINT_CODES.items()}


def test_findings_use_the_documented_severity() -> None:
    policy = make(rule("a", "allow", "*"))
    finding = lint_policy(policy)[0]
    assert finding.severity == LINT_CODES[finding.code][0]


# ---------- L001 shadowed ----------

def test_a_narrow_allow_under_a_wide_block_is_shadowed() -> None:
    policy = make(
        rule("narrow-allow", "allow", when=LABEL_PUBLIC),
        rule("wide-block", "block", "file.*"),
    )
    found = lint_policy(policy, registry=default_registry())
    assert [f.code for f in found] == ["L001"]
    assert found[0].rule_ids == ("narrow-allow", "wide-block")
    assert found[0].severity == "warning"


def test_a_narrow_approval_under_a_block_is_shadowed() -> None:
    policy = make(
        rule("ask", "require_approval", when=LABEL_TOP),
        rule("deny", "block", "file.*"),
    )
    assert codes(policy) == ["L001"]


def test_a_narrow_block_under_a_wide_allow_is_not_a_problem() -> None:
    policy = make(rule("exception", "block", when=LABEL_TOP), rule("wide", "allow", "file.*"))
    assert "L001" not in codes(policy)


def test_roles_decide_if_a_rule_is_covered() -> None:
    wide_roles = make(
        rule("a", "allow", roles="viewer", when=LABEL_PUBLIC),
        rule("b", "block", "file.*", roles="viewer, operator"),
    )
    assert codes(wide_roles) == ["L001"]
    other_way = make(
        rule("a", "allow", when=LABEL_PUBLIC),
        rule("b", "block", "file.*", roles="viewer"),
    )
    assert "L001" not in codes(other_way)


def test_a_rule_with_more_conditions_than_the_stronger_rule_is_shadowed() -> None:
    policy = make(
        rule("a", "allow", when=f"{LABEL_PUBLIC} ;; {UNTRUSTED}"),
        rule("b", "block", when=UNTRUSTED),
    )
    assert codes(policy) == ["L001"]


def test_a_stronger_rule_with_a_different_condition_does_not_cover() -> None:
    policy = make(rule("a", "allow", when=LABEL_PUBLIC), rule("b", "block", when=UNTRUSTED))
    assert codes(policy) == []


def test_different_tools_do_not_cover_each_other() -> None:
    policy = make(rule("a", "allow", "file.read"), rule("b", "block", "email.send"))
    assert codes(policy) == []


# ---------- L002 contradictory and L004 duplicate ----------

def test_allow_and_block_for_the_same_calls_are_contradictory() -> None:
    policy = make(rule("a", "allow", when=LABEL_PUBLIC), rule("b", "block", when=LABEL_PUBLIC))
    found = lint_policy(policy, registry=default_registry())
    assert [f.code for f in found] == ["L002"]
    assert found[0].severity == "error"
    assert has_errors(found)


def test_allow_and_approval_for_the_same_calls_are_contradictory() -> None:
    policy = make(rule("a", "allow"), rule("b", "require_approval"))
    assert codes(policy) == ["L002"]


def test_same_effect_for_the_same_calls_is_a_duplicate() -> None:
    policy = make(rule("a", "block", when=UNTRUSTED), rule("b", "block", when=UNTRUSTED))
    assert codes(policy) == ["L004"]


def test_a_list_and_the_same_values_written_inline_are_the_same_condition() -> None:
    inline = "{field: user.id, op: in, value: [b, a]}"
    by_list = "{field: user.id, op: in, list: ids}"
    policy = make(
        rule("a", "allow", when=inline),
        rule("b", "block", when=by_list),
        lists="lists:\n  ids:\n    - a\n    - b\n",
    )
    assert codes(policy) == ["L002"]


# ---------- L003 and L005 broad allows ----------

def test_allow_everything_is_an_error() -> None:
    found = lint_policy(make(rule("all", "allow", "*")))
    assert [f.code for f in found] == ["L003"]
    assert has_errors(found)


def test_allow_everything_with_a_condition_is_only_a_warning() -> None:
    found = lint_policy(make(rule("all", "allow", "*", when=LABEL_PUBLIC)))
    assert [f.code for f in found] == ["L005"]
    assert not has_errors(found)


def test_allow_with_a_pattern_is_a_warning() -> None:
    assert codes(make(rule("files", "allow", "file.*"))) == ["L005"]


def test_block_everything_is_fine() -> None:
    assert codes(make(rule("deny-all", "block", "*"))) == []


# ---------- L006 unused list ----------

def test_unused_list() -> None:
    policy = make(rule("a", "block"), lists="lists:\n  unused:\n    - x\n")
    found = lint_policy(policy)
    assert [f.code for f in found] == ["L006"]
    assert "unused" in found[0].message


# ---------- L007 and L008 need the tool registry ----------

def test_pattern_that_matches_no_tool() -> None:
    policy = make(rule("a", "block", "nothing.read"))
    assert codes(policy) == ["L007"]
    assert codes(make(rule("a", "block", "emial.*"))) == ["L007"]


def test_registry_checks_are_skipped_without_a_registry() -> None:
    policy = make(rule("a", "block", "nothing.read"))
    assert codes(policy, registry=False) == []


def test_unknown_argument_name() -> None:
    bad = "{field: args.recipient.registered_domain, op: eq, value: evil.com}"
    good = "{field: args.to.registered_domain, op: eq, value: evil.com}"
    assert codes(make(rule("a", "block", "email.send", when=bad))) == ["L008"]
    assert codes(make(rule("a", "block", "email.send", when=good))) == []


def test_argument_exists_for_some_matching_tool() -> None:
    cond = "{field: args.path, op: eq, value: /workspace/x}"
    assert codes(make(rule("a", "block", "*", when=cond))) == []


# ---------- L009 can never match ----------

@pytest.mark.parametrize(
    "when",
    [
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: eq, value: b}",
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: ne, value: a}",
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: in, value: [b, c]}",
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: not_in, value: [a, b]}",
        "{field: user.role, op: eq, value: viewer} ;; {field: user.role, op: eq, value: operator}",
    ],
)
def test_conditions_that_contradict_each_other(when: str) -> None:
    found = lint_policy(make(rule("dead", "block", when=when)), registry=default_registry())
    assert [f.code for f in found] == ["L009"]
    assert has_errors(found)


@pytest.mark.parametrize(
    "when",
    [
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: ne, value: b}",
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: eq, value: a}",
        "{field: user.id, op: eq, value: a} ;; {field: user.id, op: in, value: [a, b]}",
        "{field: user.id, op: eq, value: a} ;; {field: agent.id, op: eq, value: b}",
    ],
)
def test_conditions_that_are_fine_together(when: str) -> None:
    assert codes(make(rule("alive", "block", when=when))) == []


# ---------- order and helpers ----------

def test_findings_come_back_in_a_fixed_order() -> None:
    policy = make(
        rule("a", "allow", "*"),
        rule("b", "block", "nothing.read"),
        lists="lists:\n  unused:\n    - x\n",
    )
    first = lint_policy(policy, registry=default_registry())
    second = lint_policy(policy, registry=default_registry())
    assert first == second
    assert [f.code for f in first] == sorted(f.code for f in first)


def test_has_errors_ignores_warnings() -> None:
    warning = LintFinding("L001", "warning", ("a",), "x")
    error = LintFinding("L002", "error", ("a",), "x")
    assert not has_errors([warning])
    assert has_errors([warning, error])
    assert not has_errors([])