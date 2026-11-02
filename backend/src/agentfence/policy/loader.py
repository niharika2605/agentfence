"""Policy loader (Day 14).

Reads a policy from YAML text or a file and returns a checked Policy, or raises
PolicyError with every problem found. A policy that does not load is never used.

Extra YAML safety:
- Safe loader only. No custom tags, no Python objects.
- Duplicate keys are an error. Plain YAML would silently keep the last one.
- Anchors and aliases are not allowed.
- The file has a size limit.
- Wrong types are never converted. YAML reads an unquoted no, yes, on or off as a
  true or false value, and that is an error for a text field.
"""
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentfence.policy.schema import Policy, check_semantics

MAX_POLICY_BYTES = 200_000
MAX_PROBLEMS = 50


class PolicyError(Exception):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems[:MAX_PROBLEMS]
        super().__init__("policy is not valid: " + "; ".join(self.problems))


class StrictLoader(yaml.SafeLoader):
    """A safe loader that refuses duplicate keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key: {key!r}", key_node.start_mark
                    )
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    None, None, "a key must be a simple value", key_node.start_mark
                ) from exc
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _parse_yaml(text: str) -> Any:
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise PolicyError(["YAML anchors and aliases are not allowed"])
        loader = StrictLoader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = f" (line {mark.line + 1})" if mark is not None else ""
        problem = getattr(exc, "problem", None) or "invalid YAML"
        raise PolicyError([f"YAML error{line}: {problem}"]) from exc


def load_policy_text(text: object) -> Policy:
    if not isinstance(text, str):
        raise PolicyError(["policy must be text"])
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyError(["policy file is too large"])

    data = _parse_yaml(text)
    if not isinstance(data, dict):
        raise PolicyError(["policy must be a mapping with schema, name and rules"])
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        problems = []
        for error in exc.errors(include_url=False, include_context=False, include_input=False):
            where = ".".join(str(part) for part in error["loc"]) or "policy"
            problems.append(f"{where}: {error['msg']}")
        raise PolicyError(problems) from exc

    problems = check_semantics(policy)
    if problems:
        raise PolicyError(problems)
    return policy


def load_policy_file(path: str | Path) -> Policy:
    file = Path(path)
    if file.stat().st_size > MAX_POLICY_BYTES:
        raise PolicyError(["policy file is too large"])
    return load_policy_text(file.read_text(encoding="utf-8"))