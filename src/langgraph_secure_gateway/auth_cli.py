"""Admin bootstrap helpers for CLI command integration."""

from __future__ import annotations

from sqlalchemy import select

from langgraph_secure_gateway.auth.db import SessionLocal
from langgraph_secure_gateway.auth.models import User
from langgraph_secure_gateway.auth.security import hash_password


def create_or_update_admin_user(
    *,
    email: str,
    password: str,
    first_name: str | None = None,
    last_name: str | None = None,
    inactive: bool = False,
) -> str:
    """Create or update an admin user and return operation status."""
    normalized_email = email.strip().lower()
    if not normalized_email:
        raise ValueError('email must not be empty')

    with SessionLocal() as session:
        statement = select(User).where(User.email == normalized_email).limit(1)
        user = session.execute(statement).scalar_one_or_none()

        password_hash = hash_password(password)
        is_active = not inactive

        if user is None:
            user = User(
                email=normalized_email,
                first_name=first_name,
                last_name=last_name,
                password_hash=password_hash,
                is_admin=True,
                is_active=is_active,
            )
            session.add(user)
            action = 'created'
        else:
            user.password_hash = password_hash
            if first_name is not None:
                user.first_name = first_name
            if last_name is not None:
                user.last_name = last_name
            user.is_admin = True
            user.is_active = is_active
            action = 'updated'

        session.commit()

    return action
