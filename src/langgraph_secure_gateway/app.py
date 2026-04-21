"""FastAPI app wiring for auth, admin, and upstream proxy routing."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from langgraph_secure_gateway.auth.admin import mount_admin
from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import ensure_auth_schema
from langgraph_secure_gateway.auth.routes import router as auth_router
from langgraph_secure_gateway.gateway.proxy import router as proxy_router


def create_gateway_app() -> FastAPI:
    """Create and configure the secure gateway application."""
    app = FastAPI(
        title='LangGraph Secure Gateway',
        docs_url='/gateway/docs',
        redoc_url='/gateway/redoc',
        openapi_url='/gateway/openapi.json',
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.admin_session_secret,
    )
    cors_origins = [
        origin.strip() for origin in settings.cors_origins.split(',') if origin.strip()
    ]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=['*'],
            allow_headers=['*'],
        )

    @app.on_event('startup')
    async def maybe_init_auth_schema() -> None:
        if settings.auth_db_auto_migrate:
            ensure_auth_schema()

    @app.get('/healthz')
    async def healthz() -> dict[str, str]:
        return {'status': 'ok'}

    @app.get('/', include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse(url='/admin/', status_code=307)

    @app.get('/admin', include_in_schema=False)
    async def admin_redirect() -> RedirectResponse:
        return RedirectResponse(url='/admin/', status_code=307)

    mount_admin(app)
    app.include_router(auth_router)
    app.include_router(proxy_router)
    return app
