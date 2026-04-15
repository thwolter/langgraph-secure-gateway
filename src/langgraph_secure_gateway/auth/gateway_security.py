"""Bearer token helpers for gateway-level authentication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID

import jwt

from langgraph_secure_gateway.auth.models import User
from langgraph_secure_gateway.auth.security import decode_access_token


@dataclass(frozen=True)
class AuthError(Exception):
    """Raised when gateway bearer authentication fails."""

    status_code: int
    detail: str


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    user_id: UUID
    username: str
    user: User


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode('utf-8')
    if isinstance(value, str):
        return value
    return str(value)


def _header_value(headers: Mapping[Any, Any], name: str) -> str | None:
    name_lower = name.lower()

    for key, value in headers.items():
        key_text = _to_text(key)
        if key_text is None or key_text.lower() != name_lower:
            continue

        value_text = _to_text(value)
        return value_text.strip() if value_text else None

    return None


def extract_bearer_token(headers: Mapping[Any, Any]) -> str | None:
    authorization = _header_value(headers, 'authorization')
    if not authorization:
        return None

    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not token.strip():
        return None

    return token.strip()


def authenticate_bearer_from_headers(
    headers: Mapping[Any, Any], *, session: Any
) -> AuthenticatedPrincipal:
    token = extract_bearer_token(headers)
    if not token:
        raise AuthError(status_code=401, detail='Missing bearer token')

    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError as exc:
        raise AuthError(status_code=401, detail='Invalid or expired token') from exc

    subject = payload.get('sub')
    username = payload.get('username')
    if subject is None or username is None:
        raise AuthError(status_code=401, detail='Token payload is missing subject')

    try:
        user_id = UUID(str(subject))
    except (TypeError, ValueError) as exc:
        raise AuthError(status_code=401, detail='Token subject is invalid') from exc

    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthError(status_code=401, detail='User is inactive or missing')

    return AuthenticatedPrincipal(
        user_id=user_id,
        username=str(username),
        user=user,
    )
