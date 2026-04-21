"""Discovery helpers for LangGraph services reachable from the gateway."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from langgraph_secure_gateway.auth.config import settings


def _normalize_url(value: str) -> str | None:
    url = value.strip().rstrip('/')
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None
    return url


async def discover_langgraph_agents(base_url: str) -> list[dict[str, Any]]:
    """Fetch assistants from a selected LangGraph API."""

    normalized = _normalize_url(base_url)
    if normalized is None:
        return []

    async with httpx.AsyncClient(
        timeout=settings.langgraph_discovery_timeout_seconds
    ) as client:
        response = await client.post(
            f'{normalized}/assistants/search',
            json={'limit': 100, 'offset': 0},
        )
        response.raise_for_status()
        payload = response.json()

    if isinstance(payload, dict):
        items = payload.get('assistants') or payload.get('items') or payload.get('data')
    else:
        items = payload

    if not isinstance(items, list):
        return []

    agents: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        assistant_id = item.get('assistant_id') or item.get('id')
        graph_id = item.get('graph_id')
        name = item.get('name') or graph_id or assistant_id
        if assistant_id is None and graph_id is None:
            continue
        agents.append(
            {
                'assistant_id': str(assistant_id) if assistant_id is not None else None,
                'graph_id': str(graph_id) if graph_id is not None else None,
                'name': str(name) if name is not None else 'Assistant',
            }
        )

    return agents
