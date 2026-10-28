"""Static guard for the Docker isolation (Day 5).

Reads docker-compose.yml and fails if someone weakens the agent isolation.
It does not need Docker. The runtime proof is agent/check_isolation.py.
"""
from pathlib import Path
from typing import Any

import yaml

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
SECRET_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


def load() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return data


def env_names(service: dict[str, Any]) -> set[str]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return set(env)
    return {str(item).split("=", 1)[0] for item in env}


def test_agent_net_is_internal() -> None:
    assert load()["networks"]["agent_net"]["internal"] is True


def test_egress_net_is_not_internal() -> None:
    egress = load()["networks"]["egress_net"] or {}
    assert not egress.get("internal", False)


def test_agent_is_only_on_agent_net() -> None:
    assert load()["services"]["agent"]["networks"] == ["agent_net"]


def test_agent_publishes_no_ports() -> None:
    assert "ports" not in load()["services"]["agent"]


def test_gateway_bridges_both_networks() -> None:
    gateway = load()["services"]["gateway"]
    assert set(gateway["networks"]) == {"agent_net", "egress_net"}


def test_agent_is_hardened() -> None:
    agent = load()["services"]["agent"]
    assert agent["read_only"] is True
    assert agent["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in agent["security_opt"]


def test_agent_has_no_secret_like_env() -> None:
    names = env_names(load()["services"]["agent"])
    bad = [n for n in names if any(w in n.upper() for w in SECRET_WORDS)]
    assert bad == []


def test_control_service_is_never_on_agent_net() -> None:
    control = load()["services"]["agent_control"]
    assert "agent_net" not in control["networks"]
    assert "control" in control["profiles"]