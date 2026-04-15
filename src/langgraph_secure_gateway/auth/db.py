"""Database engine and session utilities for auth-related persistence."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.models import Base


def _normalize_postgres_uri(uri: str) -> str:
    """Normalize URI aliases to SQLAlchemy-compatible psycopg dialect URIs."""
    if uri.startswith('postgres://'):
        return uri.replace('postgres://', 'postgresql+psycopg://', 1)
    if uri.startswith('postgresql://'):
        return uri.replace('postgresql://', 'postgresql+psycopg://', 1)
    return uri


engine = create_engine(
    _normalize_postgres_uri(settings.postgres_uri), pool_pre_ping=True
)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, class_=Session
)


def get_session() -> Generator[Session, None, None]:
    """Provide a short-lived SQLAlchemy session."""
    with SessionLocal() as session:
        yield session


def ensure_auth_schema() -> None:
    """Create auth tables if they do not exist yet."""
    Base.metadata.create_all(bind=engine)


def reset_auth_schema() -> None:
    """Drop and recreate the Postgres public schema, then recreate auth tables."""
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA IF EXISTS public CASCADE'))
        connection.execute(text('CREATE SCHEMA public'))
    ensure_auth_schema()
