"""Reverse proxy router with JWT-based gateway protection."""

from __future__ import annotations

import json
import re
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

UPSTREAM_URL = settings.langgraph_upstream_url.rstrip('/')

PUBLIC_PATHS = {
    '/docs',
    '/openapi.json',
    '/docs/oauth2-redirect',
    '/redoc',
    '/healthz',
    '/auth/login',
}

router = APIRouter()


THREAD_RUN_PATH_RE = re.compile(r'^/threads/[^/]+/runs(?:/(?:stream|wait))?$')


def _is_run_create_path(path: str) -> bool:
    if path in {'/runs', '/runs/stream', '/runs/wait'}:
        return True
    return bool(THREAD_RUN_PATH_RE.fullmatch(path))


def _inject_run_config_user_id(payload: dict[str, Any], *, user_id: str) -> None:
    config = payload.get('config')
    if not isinstance(config, dict):
        config = {}
        payload['config'] = config

    configurable = config.get('configurable')
    if not isinstance(configurable, dict):
        configurable = {}
        config['configurable'] = configurable

    configurable['user_id'] = user_id


def _inject_bearer_security(spec: dict[str, Any]) -> dict[str, Any]:
    components = spec.setdefault('components', {})
    security_schemes = components.setdefault('securitySchemes', {})
    security_schemes['BearerAuth'] = {
        'type': 'http',
        'scheme': 'bearer',
        'bearerFormat': 'JWT',
    }

    for operations in spec.get('paths', {}).values():
        if not isinstance(operations, dict):
            continue
        for method_config in operations.values():
            if not isinstance(method_config, dict):
                continue
            method_config['security'] = [{'BearerAuth': []}]

    return spec


def _maybe_rewrite_body_for_identity(
    *,
    path: str,
    method: str,
    body: bytes,
    principal: Any | None,
) -> bytes:
    if principal is None or method.upper() != 'POST':
        return body

    if path not in {'/threads', '/threads/search', '/runs/batch'} and not _is_run_create_path(
        path
    ):
        return body

    if not body.strip():
        payload: Any = {} if path != '/runs/batch' else []
    else:
        try:
            raw_payload = json.loads(body)
        except json.JSONDecodeError:
            return body
        if path == '/runs/batch':
            if not isinstance(raw_payload, list):
                return body
        elif not isinstance(raw_payload, dict):
            return body
        payload = raw_payload

    user_id = str(principal.user_id)
    if path == '/threads':
        metadata = payload.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}
        payload['metadata'] = metadata
        metadata['owner'] = user_id
        metadata['user_id'] = user_id
    elif path == '/threads/search':
        metadata = payload.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}
        payload['metadata'] = metadata
        if not principal.user.is_admin:
            metadata['owner'] = user_id
    elif path == '/runs/batch':
        for run in payload:
            if isinstance(run, dict):
                _inject_run_config_user_id(run, user_id=user_id)
    elif _is_run_create_path(path):
        _inject_run_config_user_id(payload, user_id=user_id)

    return json.dumps(payload, separators=(',', ':')).encode('utf-8')


@router.api_route(
    '/{path:path}',
    methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    include_in_schema=False,
)
async def proxy(path: str, request: Request) -> Response:
    principal = None
    if request.url.path not in PUBLIC_PATHS and not request.url.path.startswith(
        '/admin'
    ):
        try:
            with SessionLocal() as session:
                principal = authenticate_bearer_from_headers(
                    request.headers, session=session
                )
        except AuthError as exc:
            return JSONResponse(
                status_code=exc.status_code, content={'detail': exc.detail}
            )

    upstream_url = f'{UPSTREAM_URL}/{path}'
    query_string = request.url.query
    if query_string:
        upstream_url = f'{upstream_url}?{query_string}'

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {'host', 'content-length'}
    }
    if principal is not None:
        headers['x-authenticated-user'] = principal.username
        headers['x-authenticated-user-id'] = str(principal.user_id)

    body = await request.body()
    body = _maybe_rewrite_body_for_identity(
        path=request.url.path,
        method=request.method,
        body=body,
        principal=principal,
    )

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
        if key.lower() not in {'content-length', 'transfer-encoding', 'connection'}
    }
    if request.url.path == '/openapi.json' and upstream_response.status_code == 200:
        spec = _inject_bearer_security(upstream_response.json())
        return JSONResponse(status_code=200, content=spec)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get('content-type'),
    )
