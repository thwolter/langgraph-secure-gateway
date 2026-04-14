"""Reverse proxy router with JWT-based gateway protection."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import SessionLocal
from langgraph_secure_gateway.auth.gateway_security import (
    AuthError,
    authenticate_bearer_from_headers,
)

UPSTREAM_URL = settings.langgraph_upstream_url.rstrip("/")

PUBLIC_PATHS = {
    "/docs",
    "/openapi.json",
    "/docs/oauth2-redirect",
    "/redoc",
    "/healthz",
    "/auth/login",
}

router = APIRouter()


def _inject_bearer_security(spec: dict[str, Any]) -> dict[str, Any]:
    components = spec.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    for operations in spec.get("paths", {}).values():
        if not isinstance(operations, dict):
            continue
        for method_config in operations.values():
            if not isinstance(method_config, dict):
                continue
            method_config["security"] = [{"BearerAuth": []}]

    return spec


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request) -> Response:
    user = None
    if request.url.path not in PUBLIC_PATHS and not request.url.path.startswith("/admin"):
        try:
            with SessionLocal() as session:
                user = authenticate_bearer_from_headers(request.headers, session=session)
        except AuthError as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    upstream_url = f"{UPSTREAM_URL}/{path}"
    query_string = request.url.query
    if query_string:
        upstream_url = f"{upstream_url}?{query_string}"

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length"}
    }
    if user is not None:
        headers["x-authenticated-user"] = user.username
        headers["x-authenticated-user-id"] = str(user.id)

    body = await request.body()

    async with httpx.AsyncClient(timeout=120.0) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in {"content-length", "transfer-encoding", "connection"}
    }
    if request.url.path == "/openapi.json" and upstream_response.status_code == 200:
        spec = _inject_bearer_security(upstream_response.json())
        return JSONResponse(status_code=200, content=spec)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )
