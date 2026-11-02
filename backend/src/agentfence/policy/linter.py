"""Policy linter (Day 14).

The loader says whether a policy is valid. The linter says whether it is sensible.
Findings have a code, a severity and the rule ids involved.

Errors mean the policy should not be activated. Warnings should be read by a person.

The checks are careful. A rule covers another rule only when that is certain from
the text (same or wider tool, same or wider roles, and its conditions are among the
other rule's conditions). So a finding is never a guess, but some real overlaps can
still be missed.
"""
from dataclasses import dataclass
from typing import Literal

from agentfence.models import Effect
from agentfence.policy.schema import (
    Condition,
    Policy,
    Rule,
    arg_name,
    pattern_matches,
)
from agentfence.tools.registry import ToolRegistry

Severity = Literal["error", "warning"]

# Every code and what it means. docs/policy_spec.md lists the same codes.
LINT_CODES: dict[str, tuple[Severity, str]] = {
    "L001": ("warning", "shadowed rule: a stronger rule always matches too"),
    "L002": ("error", "contradictory rules: same calls, different effects"),
    "L003": ("error", "allow rule for every tool with no conditions"),
    "L004": ("warning", "duplicate rules: same calls, same effect"),
    "L005": ("warning", "broad allow rule: a wildcard tool pattern"),
    "L006": ("warning", "unused list"),
    "L007": ("warning", "tool pattern matches no registered tool"),
    "L008": ("warning", "argument name does not exist for the tool"),
    "L009": ("error", "rule can never match: its conditions contradict each other"),
}


@dataclass(frozen=True)
class LintFinding:
    code: str
    severity: Severity
    rule_ids: tuple[str, ...]
    message: str


def has_errors(findings: list[LintFinding]) -> bool:
    return any(finding.severity == "error" for finding in findings)


def _finding(code: str, rule_ids: tuple[str, ...], detail: str) -> LintFinding:
    severity, title = LINT_CODES[code]
    return LintFinding(code, severity, rule_ids, f"{title}: {detail}")


# ---------- covering ----------

def _condition_key(policy: Policy, condition: Condition) -> tuple[str, str, object]:
    """A form of a condition that is equal when the meaning is equal."""
    if condition.list_name is not None:
        raw: object = policy.lists.get(condition.list_name, [])
    else:
        raw = condition.value
    if isinstance(raw, list):
        value: object = frozenset((type(item).__name__, item) for item in raw)
    else:
        value = (type(raw).__name__, raw)
    return condition.field, condition.op, value


def _pattern_covers(wide: str, narrow: str) -> bool:
    if wide == "*" or wide == narrow:
        return True
    return wide.endswith(".*") and narrow.startswith(wide[:-1])


def _covers(policy: Policy, wide: Rule, narrow: Rule) -> bool:
    """True if every call that matches `narrow` certainly matches `wide`."""
    for pattern in narrow.tools:
        if not any(_pattern_covers(w, pattern) for w in wide.tools):
            return False
    if wide.roles is not None:
        if narrow.roles is None or not set(narrow.roles) <= set(wide.roles):
            return False
    wide_keys = {_condition_key(policy, c) for c in wide.when}
    narrow_keys = {_condition_key(policy, c) for c in narrow.when}
    return wide_keys <= narrow_keys


def _pair_findings(policy: Policy) -> list[LintFinding]:
    findings: list[LintFinding] = []
    rules = policy.rules
    for i, first in enumerate(rules):
        for second in rules[i + 1 :]:
            first_covers = _covers(policy, first, second)  # second is inside first
            second_covers = _covers(policy, second, first)  # first is inside second
            ids = (first.id, second.id)
            if first_covers and second_covers:
                if first.effect != second.effect:
                    detail = f"'{first.id}' and '{second.id}' match the same calls"
                    findings.append(_finding("L002", ids, detail))
                else:
                    detail = f"'{first.id}' and '{second.id}' are the same rule"
                    findings.append(_finding("L004", ids, detail))
                continue
            directions = ((first, second, first_covers), (second, first, second_covers))
            for wide, narrow, covered in directions:
                if covered and wide.effect.strength > narrow.effect.strength:
                    findings.append(
                        _finding(
                            "L001",
                            (narrow.id, wide.id),
                            f"'{narrow.id}' never changes the result because '{wide.id}' "
                            "always matches too and is stronger",
                        )
                    )
    return findings


# ---------- single rule checks ----------

def _never_matches(rule: Rule, policy: Policy) -> str | None:
    """A simple proof that two conditions on one field cannot both be true."""
    by_field: dict[str, list[Condition]] = {}
    for condition in rule.when:
        by_field.setdefault(condition.field, []).append(condition)
    for field, conditions in by_field.items():
        equal = [c.value for c in conditions if c.op == "eq"]
        if len({(type(v).__name__, v) for v in equal}) > 1:
            return f"field '{field}' must equal two different values"
        for c in conditions:
            if c.op == "ne" and equal and c.value == equal[0]:
                return f"field '{field}' must equal and not equal the same value"
            if c.op in ("in", "not_in") and equal:
                items = (
                    policy.lists.get(c.list_name, []) if c.list_name is not None
                    else (c.value if isinstance(c.value, list) else [])
                )
                present = equal[0] in items
                if (c.op == "in") != present:
                    return f"field '{field}' has an equality that its list condition rules out"
    return None


def _rule_findings(policy: Policy, registry: ToolRegistry | None) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for rule in policy.rules:
        wildcard = any(p == "*" or p.endswith(".*") for p in rule.tools)
        if rule.effect is Effect.ALLOW and wildcard:
            if "*" in rule.tools and not rule.when:
                findings.append(_finding("L003", (rule.id,), f"'{rule.id}' allows every call"))
            else:
                findings.append(_finding("L005", (rule.id,), f"'{rule.id}' uses a wildcard tool"))

        reason = _never_matches(rule, policy)
        if reason:
            findings.append(_finding("L009", (rule.id,), f"'{rule.id}': {reason}"))

        if registry is None:
            continue
        matched = sorted(
            tool for tool in registry.names() if any(pattern_matches(p, tool) for p in rule.tools)
        )
        if not matched:
            findings.append(_finding("L007", (rule.id,), f"'{rule.id}' matches no registered tool"))
            continue
        for condition in rule.when:
            name = arg_name(condition.field)
            if name is None:
                continue
            owners = []
            for tool in matched:
                spec = registry.get(tool)
                if spec is not None and name in spec.args_model.model_fields:
                    owners.append(tool)
            if not owners:
                detail = f"'{rule.id}' uses args.{name}, which no matching tool has"
                findings.append(_finding("L008", (rule.id,), detail))
    return findings


def _unused_lists(policy: Policy) -> list[LintFinding]:
    used = {c.list_name for rule in policy.rules for c in rule.when if c.list_name}
    return [
        _finding("L006", (), f"list '{name}' is never used")
        for name in policy.lists
        if name not in used
    ]


def lint_policy(policy: Policy, *, registry: ToolRegistry | None = None) -> list[LintFinding]:
    """All findings for a policy, in a fixed order."""
    findings = [
        *_pair_findings(policy),
        *_rule_findings(policy, registry),
        *_unused_lists(policy),
    ]
    return sorted(findings, key=lambda f: (f.code, f.rule_ids, f.message))