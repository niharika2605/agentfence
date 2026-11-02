"""The policy schema (Day 14). It follows docs/policy_spec.md.

Two layers of checking:
1. Structure (Pydantic): known keys only, right types. Nothing is guessed or converted.
2. Meaning (check_semantics): every field, operator and value makes sense together,
   every list exists, ids are unique, tool patterns are valid.

A policy that fails either layer does not load.
"""
import re
from enum import StrEnum
from typing import Literal, TypeGuard

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from agentfence.models import Effect, Role, Sensitivity, TrustLevel

MAX_RULES = 500
MAX_LIST_ITEMS = 1000

ID_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"
LIST_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
TOOL_PATTERN = re.compile(
    r"^\*$|^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*\.\*$|^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$"
)
ARG_FIELD = re.compile(r"^args\.([a-z][a-z0-9_]*)(?:\.([a-z_]+))?$")
ARG_PARTS = frozenset(
    {"scheme", "domain", "registered_domain", "port", "path", "address", "local", "root"}
)

Op = Literal["eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"]
Scalar = StrictStr | StrictInt | StrictBool


class Kind(StrEnum):
    TEXT = "text"
    ROLE = "role"
    SENSITIVITY = "sensitivity"
    TRUST = "trust"
    BOOL = "bool"
    NUMBER = "number"
    ANY = "any"


FIXED_FIELDS: dict[str, Kind] = {
    "tool.name": Kind.TEXT,
    "tool.server": Kind.TEXT,
    "user.id": Kind.TEXT,
    "user.role": Kind.ROLE,
    "agent.id": Kind.TEXT,
    "resource.label": Kind.SENSITIVITY,
    "destination.trust": Kind.TRUST,
    "session.sensitivity": Kind.SENSITIVITY,
    "session.untrusted_content": Kind.BOOL,
    "session.call_count": Kind.NUMBER,
    "session.denied_count": Kind.NUMBER,
    "time.hour_utc": Kind.NUMBER,
}

EQUALITY = ("eq", "ne", "in", "not_in", "exists")
ORDERED = ("gt", "gte", "lt", "lte")
OPS_BY_KIND: dict[Kind, tuple[str, ...]] = {
    Kind.TEXT: EQUALITY,
    Kind.ROLE: EQUALITY,
    Kind.TRUST: EQUALITY,
    Kind.BOOL: ("eq", "ne", "exists"),
    Kind.SENSITIVITY: (*EQUALITY, *ORDERED),
    Kind.NUMBER: (*EQUALITY, *ORDERED),
    Kind.ANY: (*EQUALITY, *ORDERED),
}


def field_kind(name: str) -> Kind | None:
    if name in FIXED_FIELDS:
        return FIXED_FIELDS[name]
    match = ARG_FIELD.match(name)
    if match and (match.group(2) is None or match.group(2) in ARG_PARTS):
        return Kind.ANY
    return None


def arg_name(field: str) -> str | None:
    """The argument name in a field like args.to.registered_domain, or None."""
    match = ARG_FIELD.match(field)
    return match.group(1) if match else None


def pattern_matches(pattern: str, tool: str) -> bool:
    """Tool pattern rules from the spec: exact name, 'name.*' or '*'."""
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return tool.startswith(pattern[:-1])
    return pattern == tool


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: StrictStr = Field(min_length=1, max_length=100)
    op: Op
    value: Scalar | list[Scalar] | None = None
    list_name: StrictStr | None = Field(default=None, alias="list")


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(pattern=ID_PATTERN, max_length=100)
    effect: Effect
    tool: StrictStr | list[StrictStr]
    reason: StrictStr = Field(min_length=1, max_length=500)
    roles: list[Role] | None = None
    priority: StrictInt = Field(default=100, ge=0, le=1000)
    when: list[Condition] = Field(default_factory=list)

    @property
    def tools(self) -> tuple[str, ...]:
        return (self.tool,) if isinstance(self.tool, str) else tuple(self.tool)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt = Field(alias="schema")
    name: StrictStr = Field(pattern=NAME_PATTERN, max_length=100)
    lists: dict[StrictStr, list[StrictStr | StrictInt]] = Field(default_factory=dict)
    rules: list[Rule] = Field(min_length=1, max_length=MAX_RULES)


# ---------- meaning checks ----------

def _short(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "?", text)[:60]


def _is_whole(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _number_in_range(field: str, number: int) -> bool:
    if field == "time.hour_utc":
        return 0 <= number <= 23
    if field.startswith("session."):
        return number >= 0
    return True


def value_problem(kind: Kind, field: str, value: object) -> str | None:
    """Why this single value does not fit the field, or None."""
    if kind is Kind.TEXT:
        ok = isinstance(value, str) and value != ""
    elif kind is Kind.ROLE:
        ok = isinstance(value, str) and value in {r.value for r in Role}
    elif kind is Kind.SENSITIVITY:
        ok = isinstance(value, str) and value in {s.value for s in Sensitivity}
    elif kind is Kind.TRUST:
        ok = isinstance(value, str) and value in {t.value for t in TrustLevel}
    elif kind is Kind.BOOL:
        ok = isinstance(value, bool)
    elif kind is Kind.NUMBER:
        ok = _is_whole(value) and _number_in_range(field, value)
    else:  # ANY: an argument value, text or whole number
        ok = (isinstance(value, str) and value != "") or _is_whole(value)
    return None if ok else f"value does not fit field '{_short(field)}' ({kind.value})"


def _condition_problems(
    policy: Policy, rule: Rule, index: int, condition: Condition
) -> list[str]:
    where = f"rule '{rule.id}' condition {index + 1}"
    kind = field_kind(condition.field)
    if kind is None:
        return [f"{where}: unknown field '{_short(condition.field)}'"]
    op = condition.op
    if op not in OPS_BY_KIND[kind]:
        return [f"{where}: operator '{op}' cannot be used with field '{_short(condition.field)}'"]

    value, list_name = condition.value, condition.list_name
    if value is not None and list_name is not None:
        return [f"{where}: use only one of value or list"]
    if value is None and list_name is None:
        return [f"{where}: needs one of value or list"]

    if op == "exists":
        if not isinstance(value, bool):
            return [f"{where}: 'exists' needs value: true or value: false"]
        return []

    problems: list[str] = []
    if op in ("in", "not_in"):
        if list_name is not None:
            items = policy.lists.get(list_name)
            if items is None:
                return [f"{where}: unknown list '{_short(list_name)}'"]
            source = f"list '{list_name}'"
        else:
            if not isinstance(value, list):
                return [f"{where}: '{op}' needs a list of values"]
            items = list(value)
            source = "values"
        if not items:
            return [f"{where}: {source} is empty"]
        for item in items:
            problem = value_problem(kind, condition.field, item)
            if problem:
                problems.append(f"{where}: {source}: {problem}")
                break
        return problems

    if list_name is not None:
        return [f"{where}: '{op}' takes a value, not a list"]
    if isinstance(value, list):
        return [f"{where}: '{op}' takes one value, not a list"]
    if op in ORDERED and kind is Kind.ANY and not _is_whole(value):
        return [f"{where}: '{op}' needs a whole number"]
    problem = value_problem(kind, condition.field, value)
    return [f"{where}: {problem}"] if problem else []


def check_semantics(policy: Policy) -> list[str]:
    """Every problem found in a structurally valid policy. Empty means it is valid."""
    problems: list[str] = []
    if policy.schema_version != 1:
        problems.append("schema must be 1")

    for name, items in policy.lists.items():
        if not LIST_NAME.match(name):
            problems.append(f"list name '{_short(name)}' is not valid")
        if not items:
            problems.append(f"list '{_short(name)}' is empty")
        if len(items) > MAX_LIST_ITEMS:
            problems.append(f"list '{_short(name)}' has too many items")

    seen: set[str] = set()
    for rule in policy.rules:
        if rule.id in seen:
            problems.append(f"duplicate rule id '{rule.id}'")
        seen.add(rule.id)

        tools = rule.tools
        if not tools:
            problems.append(f"rule '{rule.id}': tool list is empty")
        for pattern in tools:
            if not TOOL_PATTERN.match(pattern):
                problems.append(f"rule '{rule.id}': bad tool pattern '{_short(pattern)}'")
        if rule.roles is not None:
            if not rule.roles:
                problems.append(f"rule '{rule.id}': roles list is empty")
            if len(set(rule.roles)) != len(rule.roles):
                problems.append(f"rule '{rule.id}': roles list repeats a role")
        for index, condition in enumerate(rule.when):
            problems.extend(_condition_problems(policy, rule, index, condition))
    return problems
