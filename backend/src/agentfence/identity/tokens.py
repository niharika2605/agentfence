"""Signed session tokens (Day 13).

A token binds one user, one agent and one session to a role and a list of tools
(the scope). The gateway signs it. The agent only carries it. The agent cannot
change what is inside, because the signature would no longer match.

Wire format:  af1.<claims>.<signature>   (claims and signature are base64url)

Rules:
- The signature is checked before the claims are read.
- A token is valid only for the session it was issued for.
- A token expires, and can be revoked.
- The scope lists exact tools or 'name.*' patterns. There is no '*'.
- A scope tool must be allowed for the role. A token cannot widen a role.
- Failures raise IdentityError. Its code is for the audit log. The text that goes
  back to the agent is always the same.
"""
import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentfence.identity.roles import role_allows_tool, tools_for
from agentfence.models import Role

PREFIX = "af1"
MIN_KEY_BYTES = 32
MAX_TOKEN_CHARS = 2048
DEFAULT_TTL_SECONDS = 3600
MAX_TTL_SECONDS = 8 * 3600
MAX_SCOPE_ENTRIES = 50

ID_PATTERN = r"^[A-Za-z0-9._:@-]{1,100}$"
SCOPE_PATTERN = re.compile(
    r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$|^[a-z][a-z0-9_-]*\.\*$"
)


class IdentityError(Exception):
    """A token could not be trusted. The code is for logs, never for the agent."""

    def __init__(self, code: str) -> None:
        super().__init__("identity could not be verified")
        self.code = code


class Claims(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    v: int = Field(ge=1, le=1)
    jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    sub: str = Field(pattern=ID_PATTERN)
    agent: str = Field(pattern=ID_PATTERN)
    sid: str = Field(pattern=ID_PATTERN)
    role: Literal["viewer", "operator", "administrator"]
    scope: list[str] = Field(min_length=1, max_length=MAX_SCOPE_ENTRIES)
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)


@dataclass(frozen=True)
class Identity:
    """A verified caller. Built only from a token that passed every check."""

    token_id: str
    user_id: str
    agent_id: str
    session_id: str
    role: Role
    scope: tuple[str, ...]
    expires_at: int

    def allows_tool(self, tool: str) -> bool:
        return scope_allows(self.scope, tool)


def scope_allows(scope: Iterable[str], tool: str) -> bool:
    for entry in scope:
        if entry == tool:
            return True
        if entry.endswith(".*") and tool.startswith(entry[:-1]):
            return True
    return False


def generate_key() -> bytes:
    """A new random signing key. Keep it out of the code and out of git."""
    return secrets.token_bytes(MIN_KEY_BYTES)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise IdentityError("bad_format")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise IdentityError("bad_format") from exc


class TokenService:
    def __init__(self, key: bytes, *, clock: Callable[[], int] | None = None) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"signing key must be at least {MIN_KEY_BYTES} bytes")
        self._key = key
        self._clock = clock or (lambda: int(time.time()))
        self._revoked: set[str] = set()

    def _sign(self, signing_input: str) -> str:
        digest = hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest()
        return _b64encode(digest)

    def issue(
        self,
        *,
        user_id: str,
        agent_id: str,
        session_id: str,
        role: Role,
        scope: Iterable[str],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> str:
        scope_list = list(dict.fromkeys(scope))
        if not scope_list:
            raise ValueError("a token needs a scope")
        if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError(f"ttl must be from 1 to {MAX_TTL_SECONDS} seconds")
        for entry in scope_list:
            if not SCOPE_PATTERN.match(entry):
                raise ValueError(f"bad scope entry: {entry!r}")
            if not entry.endswith(".*") and not role_allows_tool(role, entry):
                raise ValueError(f"scope entry is not allowed for this role: {entry!r}")
            if entry.endswith(".*") and not any(
                tool.startswith(entry[:-1]) for tool in tools_for(role)
            ):
                raise ValueError(f"scope pattern matches nothing for this role: {entry!r}")
        now = self._clock()
        try:
            claims = Claims(
                v=1,
                jti=secrets.token_hex(16),
                sub=user_id,
                agent=agent_id,
                sid=session_id,
                role=role.value,
                scope=scope_list,
                iat=now,
                exp=now + ttl_seconds,
            )
        except ValidationError as exc:
            raise ValueError("user, agent or session id has unsupported characters") from exc
        payload = json.dumps(claims.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        body = f"{PREFIX}.{_b64encode(payload.encode('utf-8'))}"
        return f"{body}.{self._sign(body)}"

    def verify(self, token: object, *, session_id: str | None = None) -> Identity:
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
            raise IdentityError("bad_format")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise IdentityError("bad_format")
        body = f"{parts[0]}.{parts[1]}"
        if not hmac.compare_digest(self._sign(body), parts[2]):
            raise IdentityError("bad_signature")
        try:
            claims = Claims.model_validate(json.loads(_b64decode(parts[1])))
        except (ValidationError, ValueError) as exc:
            raise IdentityError("bad_claims") from exc

        now = self._clock()
        if claims.iat > now:
            raise IdentityError("not_yet_valid")
        if now >= claims.exp:
            raise IdentityError("expired")
        if claims.jti in self._revoked:
            raise IdentityError("revoked")
        if session_id is not None and claims.sid != session_id:
            raise IdentityError("wrong_session")
        return Identity(
            token_id=claims.jti,
            user_id=claims.sub,
            agent_id=claims.agent,
            session_id=claims.sid,
            role=Role(claims.role),
            scope=tuple(claims.scope),
            expires_at=claims.exp,
        )

    def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)