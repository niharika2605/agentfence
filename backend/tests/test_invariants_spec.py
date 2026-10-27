"""Placeholders for the 7 security invariants (I1 to I7).

The test names are fixed on Day 2 (see docs/invariants.md).
Each test is skipped until its real day arrives.
When you fill one in, remove its skip marker.
"""
import pytest


def test_i1_blocked_call_never_reaches_executor() -> None:
    pytest.skip("Filled in on Day 16")


def test_i2_approval_is_single_use_expiring_and_bound() -> None:
    pytest.skip("Filled in on Day 24")


def test_i3_untrusted_content_cannot_raise_privileges() -> None:
    pytest.skip("Filled in on Day 20")


def test_i4_failed_canonicalization_or_validation_is_denied() -> None:
    pytest.skip("Filled in on Day 16")


def test_i5_sensitive_tools_denied_when_dependencies_down() -> None:
    pytest.skip("Filled in on Day 28")


def test_i6_every_attempt_produces_an_audit_event() -> None:
    pytest.skip("Filled in on Day 28")


def test_i7_client_supplied_decisions_are_ignored() -> None:
    pytest.skip("Filled in on Day 16")