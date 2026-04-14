"""Auth-related configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Runtime settings for authentication and admin session handling."""

    postgres_uri: str = (
        "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
    )
    jwt_secret: str = "development-only-jwt-secret-at-least-32"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    admin_session_secret: str = "development-only-admin-session-secret-32"
    langgraph_upstream_url: str = "http://langgraph-api:8000"
    auth_db_auto_init: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = AuthSettings()
