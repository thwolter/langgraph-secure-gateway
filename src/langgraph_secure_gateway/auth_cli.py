"""Admin bootstrap helpers for CLI command integration."""

from __future__ import annotations

from sqlalchemy import select

from langgraph_secure_gateway.auth.db import SessionLocal
from langgraph_secure_gateway.auth.models import User
from langgraph_secure_gateway.auth.security import hash_password


def create_or_update_admin_user(*, username: str, password: str, inactive: bool = False) -> str:
    """Create or update an admin user and return operation status."""
    normalized = username.strip()
    if not normalized:
        raise ValueError("username must not be empty")

    with SessionLocal() as session:
        statement = select(User).where(User.username == normalized).limit(1)
        user = session.execute(statement).scalar_one_or_none()

        password_hash = hash_password(password)
        is_active = not inactive

        if user is None:
            user = User(
                username=normalized,
                password_hash=password_hash,
                is_admin=True,
                is_active=is_active,
            )
            session.add(user)
            action = "created"
        else:
            user.password_hash = password_hash
            user.is_admin = True
            user.is_active = is_active
            action = "updated"

        session.commit()

    return action
