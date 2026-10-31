"""Tests for signed session tokens (Day 13)."""
import base64
import json
import string
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from agentfence.identity.tokens import (
    MAX_TTL_SECONDS,
    IdentityError,
    TokenService,
    generate_key,
    scope_allows,
)
from agentfence.models import Role

KEY = b"k" * 32
OTHER_KEY = b"z" * 32


class Clock:
    def __init__(self, now: int = 1_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def make_service(clock: Clock | None = None, key: bytes = KEY) -> TokenService:
    return TokenService(key, clock=clock or Clock())


def issue(service: TokenService, **overrides: Any) -> str:
    data: dict[str, Any] = {
        "user_id": "user-1",
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "role": Role.OPERATOR,
        "scope": ["file.read", "email.send"],
    }
    data.update(overrides)
    return service.issue(**data)


def code_of(service: TokenService, token: object, **kwargs: Any) -> str:
    with pytest.raises(IdentityError) as caught:
        service.verify(token, **kwargs)
    return caught.value.code


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def signed(service: TokenService, claims: dict[str, Any]) -> str:
    """A token with a VALID signature around the given claims (for testing bad claims)."""
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":"))
    body = f"af1.{b64(payload.encode())}"
    return f"{body}.{service._sign(body)}"


def good_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "v": 1,
        "jti": "0" * 32,
        "sub": "user-1",
        "agent": "agent-1",
        "sid": "sess-1",
        "role": "operator",
        "scope": ["file.read"],
        "iat": 1_000_000,
        "exp": 1_003_600,
    }
    claims.update(overrides)
    return claims


# ---------- keys and roles ----------

def test_the_role_names_in_the_claims_match_the_role_enum() -> None:
    from typing import get_args

    from agentfence.identity.tokens import Claims

    allowed = set(get_args(Claims.model_fields["role"].annotation))
    assert allowed == {role.value for role in Role}


def test_short_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        TokenService(b"short")


def test_generated_keys_are_long_and_different() -> None:
    assert len(generate_key()) >= 32
    assert generate_key() != generate_key()


# ---------- issue and verify ----------

def test_round_trip() -> None:
    service = make_service()
    identity = service.verify(issue(service), session_id="sess-1")
    assert identity.user_id == "user-1"
    assert identity.agent_id == "agent-1"
    assert identity.session_id == "sess-1"
    assert identity.role is Role.OPERATOR
    assert identity.scope == ("file.read", "email.send")
    assert identity.expires_at == 1_000_000 + 3600
    assert len(identity.token_id) == 32


def test_tokens_differ_even_for_the_same_inputs() -> None:
    service = make_service()
    assert issue(service) != issue(service)


def test_token_has_three_url_safe_parts() -> None:
    parts = issue(make_service()).split(".")
    assert parts[0] == "af1"
    assert len(parts) == 3
    safe = set(string.ascii_letters + string.digits + "-_")
    assert all(set(part) <= safe for part in parts[1:])


def test_duplicate_scope_entries_are_merged() -> None:
    service = make_service()
    identity = service.verify(issue(service, scope=["file.read", "file.read", "email.send"]))
    assert identity.scope == ("file.read", "email.send")


def test_verify_without_a_session_skips_the_session_check() -> None:
    service = make_service()
    assert service.verify(issue(service)).session_id == "sess-1"


# ---------- issue rules ----------

@pytest.mark.parametrize(
    "scope",
    [
        [],
        ["*"],
        ["File.Read"],
        ["file"],
        ["file.read "],
        ["file..read"],
        ["file.*.x"],
        ["code.run"],
        ["shell.run"],
        ["email.*", "code.*"],
        ["nothing.*"],
    ],
)
def test_bad_scopes_are_not_issued_for_an_operator(scope: list[str]) -> None:
    with pytest.raises(ValueError):
        issue(make_service(), scope=scope)


def test_a_token_cannot_widen_a_role() -> None:
    service = make_service()
    with pytest.raises(ValueError, match="not allowed for this role"):
        issue(service, role=Role.VIEWER, scope=["email.send"])
    with pytest.raises(ValueError, match="matches nothing"):
        issue(service, role=Role.VIEWER, scope=["code.*"])
    assert issue(service, role=Role.VIEWER, scope=["file.read", "db.*"])
    assert issue(service, role=Role.ADMINISTRATOR, scope=["code.run", "email.*"])


@pytest.mark.parametrize("ttl", [0, -1, MAX_TTL_SECONDS + 1])
def test_bad_ttl_values(ttl: int) -> None:
    with pytest.raises(ValueError, match="ttl"):
        issue(make_service(), ttl_seconds=ttl)


@pytest.mark.parametrize("field", ["user_id", "agent_id", "session_id"])
@pytest.mark.parametrize("value", ["", "a b", "a/b", "a\nb", "x" * 101, "caf\u00e9"])
def test_bad_ids_are_not_issued(field: str, value: str) -> None:
    with pytest.raises(ValueError, match="unsupported characters"):
        issue(make_service(), **{field: value})


def test_longest_allowed_ttl_works() -> None:
    service = make_service()
    identity = service.verify(issue(service, ttl_seconds=MAX_TTL_SECONDS))
    assert identity.expires_at == 1_000_000 + MAX_TTL_SECONDS


# ---------- tampering ----------

def test_changing_the_claims_breaks_the_signature() -> None:
    service = make_service()
    prefix, claims, signature = issue(service).split(".")
    forged = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    forged["role"] = "administrator"
    new_claims = b64(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode())
    assert code_of(service, f"{prefix}.{new_claims}.{signature}") == "bad_signature"


def test_a_signature_from_another_key_is_rejected() -> None:
    token = issue(make_service(key=OTHER_KEY))
    assert code_of(make_service(), token) == "bad_signature"


def test_changing_the_signature_is_rejected() -> None:
    service = make_service()
    token = issue(service)
    broken = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    assert code_of(service, broken) == "bad_signature"


@pytest.mark.parametrize(
    "token",
    [
        None, 5, b"af1.a.b", ["af1"], "", "af1", "af1.a", "af1.a.b.c", "af2.a.b", "AF1.a.b",
        "x" * 2049,
    ],
)
def test_malformed_tokens(token: object) -> None:
    assert code_of(make_service(), token) == "bad_format"


def test_non_base64_characters_in_the_claims() -> None:
    service = make_service()
    body = "af1.%%%%"
    token = f"{body}.{service._sign(body)}"
    assert code_of(service, token) == "bad_format"


# ---------- signed but wrong claims ----------

@pytest.mark.parametrize(
    "claims",
    [
        {**good_claims(), "extra": 1},
        {k: v for k, v in good_claims().items() if k != "scope"},
        good_claims(role="root"),
        good_claims(role="Operator"),
        good_claims(v=2),
        good_claims(scope=[]),
        good_claims(scope="file.read"),
        good_claims(jti="short"),
        good_claims(sub="a b"),
        good_claims(iat="1000000"),
        good_claims(exp=True),
        good_claims(iat=-1),
    ],
)
def test_signed_tokens_with_bad_claims_are_rejected(claims: dict[str, Any]) -> None:
    service = make_service()
    assert code_of(service, signed(service, claims)) == "bad_claims"


def test_signed_garbage_is_rejected() -> None:
    service = make_service()
    body = f"af1.{b64(b'not json at all')}"
    assert code_of(service, f"{body}.{service._sign(body)}") == "bad_claims"
    body = f"af1.{b64(b'[1,2,3]')}"
    assert code_of(service, f"{body}.{service._sign(body)}") == "bad_claims"


# ---------- time, session, revoke ----------

def test_expiry() -> None:
    clock = Clock()
    service = make_service(clock)
    token = issue(service, ttl_seconds=60)
    clock.now += 59
    assert service.verify(token)
    clock.now += 1
    assert code_of(service, token) == "expired"
    clock.now += 10_000
    assert code_of(service, token) == "expired"


def test_a_token_from_the_future_is_rejected() -> None:
    service = make_service(Clock(1_000_000))
    token = signed(service, good_claims(iat=1_000_500, exp=1_004_000))
    assert code_of(service, token) == "not_yet_valid"


def test_wrong_session() -> None:
    service = make_service()
    assert code_of(service, issue(service), session_id="sess-2") == "wrong_session"


def test_revoked_token() -> None:
    service = make_service()
    token = issue(service)
    identity = service.verify(token)
    service.revoke(identity.token_id)
    assert code_of(service, token) == "revoked"
    other = issue(service)
    assert service.verify(other)


def test_revoking_an_unknown_id_is_harmless() -> None:
    service = make_service()
    service.revoke("f" * 32)
    assert service.verify(issue(service))


# ---------- scope matching ----------

@pytest.mark.parametrize(
    ("scope", "tool", "expected"),
    [
        (["file.read"], "file.read", True),
        (["file.read"], "file.write", False),
        (["file.*"], "file.read", True),
        (["file.*"], "file.read.deep", True),
        (["file.*"], "filesystem.read", False),
        (["file.*"], "file", False),
        (["email.send", "file.*"], "email.send", True),
        ([], "file.read", False),
    ],
)
def test_scope_allows(scope: list[str], tool: str, expected: bool) -> None:
    assert scope_allows(scope, tool) is expected


def test_identity_allows_tool_uses_its_scope() -> None:
    service = make_service()
    identity = service.verify(issue(service, scope=["file.read", "email.*"]))
    assert identity.allows_tool("email.send")
    assert not identity.allows_tool("db.query")


# ---------- properties ----------

@settings(max_examples=300, deadline=None)
@given(st.data())
def test_property_any_single_change_breaks_the_token(data: st.DataObject) -> None:
    service = make_service()
    token = issue(service)
    position = data.draw(st.integers(min_value=0, max_value=len(token) - 1))
    replacement = data.draw(st.characters(min_codepoint=33, max_codepoint=126))
    if replacement == token[position]:
        return
    changed = token[:position] + replacement + token[position + 1 :]
    with pytest.raises(IdentityError):
        service.verify(changed)


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=200))
def test_property_garbage_only_raises_identity_error(text: str) -> None:
    try:
        make_service().verify(text)
    except IdentityError:
        pass
    else:
        raise AssertionError("garbage was accepted")


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=32, max_size=64), st.binary(min_size=32, max_size=64))
def test_property_a_token_only_verifies_with_its_own_key(key_a: bytes, key_b: bytes) -> None:
    # HMAC pads short keys with zero bytes, so keys that differ only by trailing
    # zero bytes are the same key. Real keys come from generate_key(), not from this.
    assume(key_a.rstrip(b"\x00") != key_b.rstrip(b"\x00"))
    token = issue(TokenService(key_a, clock=Clock()))
    TokenService(key_a, clock=Clock()).verify(token)
    with pytest.raises(IdentityError):
        TokenService(key_b, clock=Clock()).verify(token)