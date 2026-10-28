"""Keeps docs/related_work.md complete (Day 4)."""
from pathlib import Path

NOTE = Path(__file__).resolve().parents[2] / "docs" / "related_work.md"

REQUIRED_SECTIONS = [
    "## CaMeL",
    "## Progent",
    "## AgentDojo",
    "## InjecAgent",
    "## MCP security guidance",
    "## Invariant Guardrails and MCP-Scan",
    "## LlamaFirewall",
    "## Comparison table",
    "## What AgentFence does differently",
    "## What AgentFence does NOT claim",
]


def test_related_work_has_all_sections() -> None:
    text = NOTE.read_text(encoding="utf-8")
    for heading in REQUIRED_SECTIONS:
        assert heading in text, f"missing section: {heading}"


def test_related_work_has_no_unfilled_markers() -> None:
    text = NOTE.read_text(encoding="utf-8")
    assert "[FILL]" not in text, "replace every [FILL] with your own words"