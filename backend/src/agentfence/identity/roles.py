"""Roles and what each role may do (Day 13).

A role is a ceiling, not a grant. The policy engine (Day 15) decides the rest.
Rules for this table:
- Default deny: a tool that is not listed for a role is not allowed.
- No inheritance: every role lists its tools in full.
- Tools that read labeled resources have a ceiling: the most sensitive label the
  role may touch at all. Above the ceiling the answer is block, not approval.
- If the label of a resource is unknown, the answer is deny.

The same table is written in docs/roles.md. A test keeps them equal.
"""
from dataclasses import dataclass

from agentfence.models import Role, Sensitivity


@dataclass(frozen=True)
class ToolPermission:
    # None means the tool does not read labeled resources, so there is no ceiling.
    max_sensitivity: Sensitivity | None = None


@dataclass(frozen=True)
class RoleCheck:
    allowed: bool
    reason: str


ROLE_PERMISSIONS: dict[Role, dict[str, ToolPermission]] = {
    Role.VIEWER: {
        "file.read": ToolPermission(Sensitivity.INTERNAL),
        "db.query": ToolPermission(Sensitivity.INTERNAL),
    },
    Role.OPERATOR: {
        "file.read": ToolPermission(Sensitivity.SECRET),
        "db.query": ToolPermission(Sensitivity.SECRET),
        "email.send": ToolPermission(),
    },
    Role.ADMINISTRATOR: {
        "file.read": ToolPermission(Sensitivity.SECRET),
        "db.query": ToolPermission(Sensitivity.SECRET),
        "email.send": ToolPermission(),
        "code.run": ToolPermission(),
    },
}


def tools_for(role: Role) -> frozenset[str]:
    return frozenset(ROLE_PERMISSIONS[role])


def role_allows_tool(role: Role, tool: str) -> bool:
    return tool in ROLE_PERMISSIONS[role]


def check_role(role: Role, tool: str, label: Sensitivity | None = None) -> RoleCheck:
    """Can this role use this tool on a resource with this label?"""
    permission = ROLE_PERMISSIONS[role].get(tool)
    if permission is None:
        return RoleCheck(False, "role is not allowed to use this tool")
    ceiling = permission.max_sensitivity
    if ceiling is None:
        return RoleCheck(True, "role may use this tool")
    if label is None:
        return RoleCheck(False, "the label of the resource is unknown")
    if label.rank > ceiling.rank:
        return RoleCheck(False, "role may not access resources this sensitive")
    return RoleCheck(True, "role may use this tool on this resource")