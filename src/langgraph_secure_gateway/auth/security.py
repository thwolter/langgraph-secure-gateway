"""Password hashing and JWT token helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from passlib.context import CryptContext

from langgraph_secure_gateway.auth.config import settings

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, password_hash)


def hash_password(password: str) -> str:
    """Hash a password for secure database storage."""
    return pwd_context.hash(password)


def create_access_token(*, user_id: UUID) -> str:
    """Create a signed JWT access token for a specific user."""
    now = datetime.now(tz=UTC)
    expire_at = now + timedelta(minutes=settings.jwt_expire_minutes)
    payload: dict[str, Any] = {
        'sub': str(user_id),
        'iat': int(now.timestamp()),
        'exp': int(expire_at.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a signed JWT access token."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
