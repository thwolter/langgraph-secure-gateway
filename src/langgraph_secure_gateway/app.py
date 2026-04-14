"""FastAPI app wiring for auth, admin, and upstream proxy routing."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from langgraph_secure_gateway.auth.admin import mount_admin
from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.routes import router as auth_router
from langgraph_secure_gateway.gateway.proxy import router as proxy_router


def create_gateway_app() -> FastAPI:
    """Create and configure the secure gateway application."""
    app = FastAPI(
        title="LangGraph Secure Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.admin_session_secret,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/admin", include_in_schema=False)
    async def admin_redirect() -> RedirectResponse:
        return RedirectResponse(url="/admin/", status_code=307)

    mount_admin(app)
    app.include_router(auth_router)
    app.include_router(proxy_router)
    return app
