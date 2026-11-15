"""Authentication and role-based access control.

- Passwords: bcrypt hashes in ``users``; never logged.
- Tokens: HS256 JWT (PyJWT) with ``sub``, ``role``, ``exp``. The signing secret
  comes **only** from the environment (``SENTINEL_JWT_SECRET``, >= 32 chars);
  the app refuses to start without it.
- Roles and permissions are one table (:data:`PERMISSIONS`); executives are
  read-only. Every write endpoint also writes ``audit_log``.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

import bcrypt
import jwt

JWT_SECRET_ENV = "SENTINEL_JWT_SECRET"
TOKEN_MINUTES = 60


class Role(StrEnum):
    ANALYST = "analyst"
    MANAGER = "manager"
    ADMIN = "admin"
    EXECUTIVE = "executive"


PERMISSIONS: dict[str, frozenset[Role]] = {
    "read": frozenset(Role),
    "read.raw": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "feedback.create": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "incident.update": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "incident.build": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "report.create": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "approval.request": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "approval.decide": frozenset({Role.MANAGER, Role.ADMIN}),
    "action.execute": frozenset({Role.MANAGER, Role.ADMIN}),
    "copilot.ask": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "investigation.run": frozenset({Role.ANALYST, Role.MANAGER, Role.ADMIN}),
    "audit.read": frozenset({Role.MANAGER, Role.ADMIN}),
    "user.manage": frozenset({Role.ADMIN}),
}


class AuthError(Exception):
    pass


def jwt_secret() -> str:
    secret = os.environ.get(JWT_SECRET_ENV, "")
    if len(secret) < 32:
        raise AuthError(f"{JWT_SECRET_ENV} must be set in the environment (>= 32 characters)")
    return secret


def hash_password(password: str, rounds: int = 12) -> str:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def issue_token(username: str, role: Role, secret: str, minutes: int = TOKEN_MINUTES,
                now: datetime | None = None) -> str:
    issued = now or datetime.now(timezone.utc)
    payload = {"sub": username, "role": role.value, "iat": int(issued.timestamp()),
               "exp": int((issued + timedelta(minutes=minutes)).timestamp())}
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> dict[str, Any]:
    try:
        payload: dict[str, Any] = jwt.decode(token, secret, algorithms=["HS256"],
                                             options={"require": ["sub", "role", "exp"]})
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {type(exc).__name__}") from exc
    if payload["role"] not in {r.value for r in Role}:
        raise AuthError("invalid token: unknown role")
    return payload


def allowed(role: Role, permission: str) -> bool:
    return role in PERMISSIONS[permission]
