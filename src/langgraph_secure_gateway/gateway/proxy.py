"""Reverse proxy router with JWT-based gateway protection."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from starlette.background import BackgroundTask

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import SessionLocal
from langgraph_secure_gateway.auth.gateway_security import (
    AuthenticatedPrincipal,
    AuthError,
    authenticate_bearer_from_headers,
)
from langgraph_secure_gateway.auth.models import Agent, UserAgentAccess

router = APIRouter()
logger = logging.getLogger(__name__)


THREAD_RUN_PATH_RE = re.compile(r'^/threads/[^/]+/runs(?:/(?:stream|wait))?$')
STREAM_PATH_RE = re.compile(
    r'^/(?:runs/(?:stream|[^/]+/stream)|threads/[^/]+/(?:stream|runs/stream|runs/[^/]+/stream))$'
)


def _is_run_create_path(path: str) -> bool:
    if path in {'/runs', '/runs/stream', '/runs/wait'}:
        return True
    return bool(THREAD_RUN_PATH_RE.fullmatch(path))


def _is_stream_path(path: str) -> bool:
    return bool(STREAM_PATH_RE.fullmatch(path))


async def _close_stream_response(
    upstream_response: httpx.Response, client: httpx.AsyncClient
) -> None:
    await upstream_response.aclose()
    await client.aclose()


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


class BodyRewriteError(Exception):
    def __init__(self, *, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _has_configurable_user_id(payload: dict[str, Any], *, user_id: str) -> bool:
    config = payload.get('config')
    if not isinstance(config, dict):
        return False
    configurable = config.get('configurable')
    if not isinstance(configurable, dict):
        return False
    return configurable.get('user_id') == user_id


def _assert_run_payload_identity(
    *,
    path: str,
    payload: Any,
    user_id: str,
) -> None:
    if path == '/runs/batch':
        if not isinstance(payload, list):
            raise BodyRewriteError(
                status_code=400,
                detail='Request body for /runs/batch must be a JSON array',
            )
        for index, run in enumerate(payload):
            if not isinstance(run, dict):
                raise BodyRewriteError(
                    status_code=400,
                    detail=f'Run at index {index} must be a JSON object',
                )
            if not _has_configurable_user_id(run, user_id=user_id):
                logger.warning(
                    'Authenticated run batch payload missing canonical user_id after rewrite',
                    extra={'path': path, 'run_index': index},
                )
                raise BodyRewriteError(
                    status_code=400,
                    detail='Run payload missing required config.configurable.user_id',
                )
        return

    if not isinstance(payload, dict):
        raise BodyRewriteError(
            status_code=400,
            detail='Run request body must be a JSON object',
        )
    if not _has_configurable_user_id(payload, user_id=user_id):
        logger.warning(
            'Authenticated run payload missing canonical user_id after rewrite',
            extra={'path': path},
        )
        raise BodyRewriteError(
            status_code=400,
            detail='Run payload missing required config.configurable.user_id',
        )


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

    if path not in {
        '/threads',
        '/threads/search',
        '/runs/batch',
    } and not _is_run_create_path(path):
        return body

    run_path = path == '/runs/batch' or _is_run_create_path(path)

    if not body.strip():
        payload: Any = {} if path != '/runs/batch' else []
    else:
        try:
            raw_payload = json.loads(body)
        except json.JSONDecodeError:
            if run_path:
                raise BodyRewriteError(
                    status_code=400,
                    detail='Run request body must be valid JSON',
                )
            return body
        if path == '/runs/batch':
            if not isinstance(raw_payload, list):
                raise BodyRewriteError(
                    status_code=400,
                    detail='Request body for /runs/batch must be a JSON array',
                )
        elif not isinstance(raw_payload, dict):
            if run_path:
                raise BodyRewriteError(
                    status_code=400,
                    detail='Run request body must be a JSON object',
                )
            return body
        payload = raw_payload

    user_id = str(principal.user_id)
    if path == '/threads':
        metadata = payload.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}
        payload['metadata'] = metadata
        metadata['owner'] = user_id
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

    if run_path:
        _assert_run_payload_identity(path=path, payload=payload, user_id=user_id)

    return json.dumps(payload, separators=(',', ':')).encode('utf-8')


def _agent_upstream_url(agent: Agent, path: str, query_string: str) -> str:
    upstream_url = f'{agent.base_url.rstrip("/")}/{path.lstrip("/")}'
    if query_string:
        upstream_url = f'{upstream_url}?{query_string}'
    return upstream_url


def _get_authorized_agent(
    *,
    agent_key: str,
    principal: AuthenticatedPrincipal,
) -> Agent | Response:
    with SessionLocal() as session:
        agent = session.execute(
            select(Agent).where(Agent.key == agent_key, Agent.is_active.is_(True))
        ).scalar_one_or_none()
        if agent is None:
            return JSONResponse(status_code=404, content={'detail': 'Agent not found'})

        access = session.execute(
            select(UserAgentAccess.id).where(
                UserAgentAccess.user_id == principal.user_id,
                UserAgentAccess.agent_id == agent.id,
            )
        ).scalar_one_or_none()
        if access is None:
            return JSONResponse(status_code=403, content={'detail': 'Agent forbidden'})

        session.expunge(agent)
        return agent


async def _proxy_agent_request(
    *, agent_key: str, path: str, request: Request
) -> Response:
    try:
        with SessionLocal() as session:
            principal = authenticate_bearer_from_headers(
                request.headers, session=session
            )
    except AuthError as exc:
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.detail})

    agent_or_response = _get_authorized_agent(
        agent_key=agent_key,
        principal=principal,
    )
    if isinstance(agent_or_response, Response):
        return agent_or_response
    agent = agent_or_response

    upstream_path = f'/{path.lstrip("/")}' if path else '/'
    upstream_url = _agent_upstream_url(agent, path, request.url.query)

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {'host', 'content-length', 'authorization'}
    }
    headers['x-authenticated-user-email'] = principal.user.email
    if principal.user.first_name:
        headers['x-authenticated-user-first-name'] = principal.user.first_name
    if principal.user.last_name:
        headers['x-authenticated-user-last-name'] = principal.user.last_name
    headers['x-authenticated-user-id'] = str(principal.user_id)
    if settings.gateway_upstream_secret:
        headers['x-gateway-upstream-secret'] = settings.gateway_upstream_secret

    body = await request.body()
    try:
        body = _maybe_rewrite_body_for_identity(
            path=upstream_path,
            method=request.method,
            body=body,
            principal=principal,
        )
    except BodyRewriteError as exc:
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.detail})

    timeout = (
        httpx.Timeout(120.0, read=None) if _is_stream_path(upstream_path) else 120.0
    )
    client = httpx.AsyncClient(timeout=timeout)
    try:
        request_to_upstream = client.build_request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
        upstream_response = await client.send(
            request_to_upstream,
            stream=_is_stream_path(upstream_path),
        )
    except httpx.RequestError as exc:
        await client.aclose()
        logger.warning(
            'Agent upstream request failed',
            extra={
                'agent_key': agent_key,
                'upstream_url': upstream_url,
                'error': str(exc),
            },
        )
        return JSONResponse(
            status_code=502,
            content={
                'detail': 'Agent upstream is unavailable',
                'agent_key': agent_key,
            },
        )

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in {'content-length', 'transfer-encoding', 'connection'}
    }
    if upstream_path == '/openapi.json' and upstream_response.status_code == 200:
        spec = _inject_bearer_security(upstream_response.json())
        await client.aclose()
        return JSONResponse(status_code=200, content=spec)

    if _is_stream_path(upstream_path):
        return StreamingResponse(
            upstream_response.aiter_raw(),
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get('content-type'),
            background=BackgroundTask(
                _close_stream_response, upstream_response, client
            ),
        )

    content = await upstream_response.aread()
    await client.aclose()

    return Response(
        content=content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get('content-type'),
    )


@router.api_route(
    '/agents/{agent_key}',
    methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    include_in_schema=False,
)
async def proxy_agent_root(agent_key: str, request: Request) -> Response:
    return await _proxy_agent_request(agent_key=agent_key, path='', request=request)


@router.api_route(
    '/agents/{agent_key}/{path:path}',
    methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    include_in_schema=False,
)
async def proxy_agent_path(agent_key: str, path: str, request: Request) -> Response:
    return await _proxy_agent_request(agent_key=agent_key, path=path, request=request)
