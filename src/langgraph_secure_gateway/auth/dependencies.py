"""FastAPI dependencies for JWT authentication and authorization checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from langgraph_secure_gateway.auth.db import get_session
from langgraph_secure_gateway.auth.models import User
from langgraph_secure_gateway.auth.security import decode_access_token


@dataclass(frozen=True)
class AuthContext:
    """Decoded and normalized user context from JWT payload."""

    user_id: UUID


def _extract_bearer_token(authorization: str | None) -> str:
    """Parse and validate a bearer token header value."""
    if not authorization:
        raise HTTPException(status_code=401, detail='Missing bearer token')

    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not token.strip():
        raise HTTPException(status_code=401, detail='Invalid authorization header')

    return token.strip()


def get_auth_context(
    authorization: Annotated[str | None, Header(alias='Authorization')] = None,
) -> AuthContext:
    """Decode Authorization header into an auth context."""
    token = _extract_bearer_token(authorization)

    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail='Invalid or expired token') from exc

    sub = payload.get('sub')
    if sub is None:
        raise HTTPException(status_code=401, detail='Token payload is missing subject')

    try:
        user_id = UUID(str(sub))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail='Token subject is invalid') from exc

    return AuthContext(user_id=user_id)


def get_current_user(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    """Load active user bound to the authenticated JWT subject."""
    user = session.get(User, auth.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail='User is inactive or missing')
    return user


def require_admin(user: Annotated[User, Depends(get_current_user)]) -> User:
    """Ensure the requester is an admin user."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Admin required'
        )
    return user
