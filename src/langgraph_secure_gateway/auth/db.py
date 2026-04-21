"""Database engine and session utilities for auth-related persistence."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from langgraph_secure_gateway.auth.config import settings


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


def _alembic_config() -> Config:
    """Build Alembic config for package-local auth migrations."""
    migrations_path = Path(__file__).resolve().parent / 'migrations'
    config = Config()
    config.set_main_option('script_location', str(migrations_path))
    config.set_main_option(
        'sqlalchemy.url', _normalize_postgres_uri(settings.postgres_uri)
    )
    return config


def migrate_auth_schema() -> None:
    """Upgrade auth schema to the latest packaged migration revision."""
    config = _alembic_config()
    with engine.begin() as connection:
        connection.execute(text('SELECT pg_advisory_lock(912301407)'))
        try:
            config.attributes['connection'] = connection
            command.upgrade(config, 'head')
        finally:
            connection.execute(text('SELECT pg_advisory_unlock(912301407)'))


def ensure_auth_schema() -> None:
    """Ensure auth schema exists and is upgraded to the latest revision."""
    migrate_auth_schema()


def reset_auth_schema() -> None:
    """Drop and recreate the Postgres public schema, then recreate auth tables."""
    with engine.begin() as connection:
        connection.execute(text('DROP SCHEMA IF EXISTS public CASCADE'))
        connection.execute(text('CREATE SCHEMA public'))
    ensure_auth_schema()
