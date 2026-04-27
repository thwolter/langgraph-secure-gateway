"""Auth-related configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Runtime settings for authentication and admin session handling."""

    postgres_uri: str = (
        'postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'
    )
    jwt_secret: str = 'development-only-jwt-secret-at-least-32'
    jwt_algorithm: str = 'HS256'
    jwt_expire_minutes: int = 60
    refresh_token_expire_days: int = 14
    refresh_cookie_name: str = 'lgsg_refresh_token'
    refresh_cookie_secure: bool = True
    refresh_cookie_samesite: str = 'lax'
    admin_session_secret: str = 'development-only-admin-session-secret-32'
    cors_origins: str = ''
    auth_db_auto_migrate: bool = False
    gateway_upstream_secret: str = ''
    langgraph_discovery_timeout_seconds: float = 2.0
    download_export_dir: str = '/tmp/langgraph-generated-files'

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )


settings = AuthSettings()
