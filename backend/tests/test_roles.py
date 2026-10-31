"""Tests for roles and the role table (Day 13)."""
import re
from pathlib import Path

import pytest

from agentfence.identity.roles import (
    ROLE_PERMISSIONS,
    check_role,
    role_allows_tool,
    tools_for,
)
from agentfence.models import Role, Sensitivity
from agentfence.tools.registry import default_registry

ROLES_DOC = Path(__file__).resolve().parents[2] / "docs" / "roles.md"
LABELS = list(Sensitivity)


def table_from_doc() -> dict[tuple[str, str], str]:
    text = ROLES_DOC.read_text(encoding="utf-8")
    pattern = r"^\| (viewer|operator|administrator) \| ([a-z.]+) \| ([a-z]+) \|$"
    rows = re.findall(pattern, text, re.M)
    return {(role, tool): label for role, tool, label in rows}


def table_from_code() -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for role, tools in ROLE_PERMISSIONS.items():
        for tool, permission in tools.items():
            ceiling = permission.max_sensitivity
            result[(role.value, tool)] = ceiling.value if ceiling else "none"
    return result


# ---------- the table in the code and in the doc ----------

def test_doc_table_equals_the_code_table() -> None:
    assert table_from_doc() == table_from_code()
    assert len(table_from_doc()) == 9


def test_every_tool_in_the_table_is_a_registered_tool() -> None:
    registered = default_registry().names()
    for tools in ROLE_PERMISSIONS.values():
        assert set(tools) <= registered


def test_every_registered_tool_is_usable_by_at_least_one_role() -> None:
    used = set().union(*(tools_for(role) for role in Role))
    assert used == default_registry().names()


def test_every_role_has_an_entry() -> None:
    assert set(ROLE_PERMISSIONS) == set(Role)


# ---------- which tools ----------

def test_viewer_can_only_read() -> None:
    assert tools_for(Role.VIEWER) == {"file.read", "db.query"}


def test_operator_can_also_send_email_but_not_run_code() -> None:
    assert tools_for(Role.OPERATOR) == {"file.read", "db.query", "email.send"}
    assert not role_allows_tool(Role.OPERATOR, "code.run")


def test_administrator_can_use_every_tool() -> None:
    assert tools_for(Role.ADMINISTRATOR) == default_registry().names()


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("tool", ["shell.run", "File.Read", "file.*", "", "file.read "])
def test_unlisted_tools_are_denied_for_every_role(role: Role, tool: str) -> None:
    assert not role_allows_tool(role, tool)
    assert not check_role(role, tool, Sensitivity.PUBLIC).allowed


def test_roles_do_not_inherit() -> None:
    operator = ROLE_PERMISSIONS[Role.OPERATOR]
    viewer = ROLE_PERMISSIONS[Role.VIEWER]
    assert operator["file.read"] is not viewer["file.read"]
    assert operator["file.read"].max_sensitivity is Sensitivity.SECRET
    assert viewer["file.read"].max_sensitivity is Sensitivity.INTERNAL


# ---------- ceilings on sensitivity ----------

@pytest.mark.parametrize("tool", ["file.read", "db.query"])
@pytest.mark.parametrize(
    ("role", "allowed_labels"),
    [
        (Role.VIEWER, {Sensitivity.PUBLIC, Sensitivity.INTERNAL}),
        (Role.OPERATOR, set(Sensitivity)),
        (Role.ADMINISTRATOR, set(Sensitivity)),
    ],
)
def test_ceiling_per_role(role: Role, allowed_labels: set[Sensitivity], tool: str) -> None:
    for label in LABELS:
        assert check_role(role, tool, label).allowed is (label in allowed_labels), label


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("tool", ["file.read", "db.query"])
def test_unknown_label_is_denied_for_tools_that_read_labeled_resources(
    role: Role, tool: str
) -> None:
    check = check_role(role, tool, None)
    assert not check.allowed
    assert "unknown" in check.reason


@pytest.mark.parametrize(
    ("role", "tool"), [(Role.OPERATOR, "email.send"), (Role.ADMINISTRATOR, "code.run")]
)
def test_tools_without_a_ceiling_ignore_the_label(role: Role, tool: str) -> None:
    for label in [None, *LABELS]:
        assert check_role(role, tool, label).allowed


def test_reasons_are_fixed_phrases() -> None:
    assert check_role(Role.VIEWER, "code.run").reason == "role is not allowed to use this tool"
    assert check_role(Role.VIEWER, "file.read", Sensitivity.SECRET).reason == (
        "role may not access resources this sensitive"
    )