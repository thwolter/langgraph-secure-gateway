"""Discovery helpers for LangGraph services reachable from the gateway."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from langgraph_secure_gateway.auth.config import settings


@dataclass(frozen=True)
class DiscoveredURL:
    url: str
    source: str


def _normalize_url(value: str) -> str | None:
    url = value.strip().rstrip('/')
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None
    return url


def _configured_urls() -> list[DiscoveredURL]:
    urls: list[DiscoveredURL] = []
    for value in settings.langgraph_discovery_urls.split(','):
        if url := _normalize_url(value):
            urls.append(DiscoveredURL(url=url, source='configured'))
    return urls


def _dedupe(urls: list[DiscoveredURL]) -> list[DiscoveredURL]:
    seen: set[str] = set()
    deduped: list[DiscoveredURL] = []
    for item in urls:
        if item.url in seen:
            continue
        seen.add(item.url)
        deduped.append(item)
    return deduped


async def discover_langgraph_urls() -> list[DiscoveredURL]:
    """Return configured URLs that look like LangGraph APIs."""

    urls = _configured_urls()
    candidates = _dedupe(urls)
    if not candidates:
        return []

    checks = await _check_urls_for_assistants(candidates)
    return [item for item, ok in zip(candidates, checks, strict=True) if ok]


async def _check_urls_for_assistants(urls: list[DiscoveredURL]) -> list[bool]:
    async with httpx.AsyncClient(
        timeout=settings.langgraph_discovery_timeout_seconds
    ) as client:
        checks = [
            _can_search_assistants(client=client, base_url=item.url) for item in urls
        ]
        return await asyncio.gather(*checks)


async def _can_search_assistants(client: httpx.AsyncClient, base_url: str) -> bool:
    try:
        response = await client.post(
            f'{base_url}/assistants/search',
            json={'limit': 1, 'offset': 0},
        )
    except httpx.HTTPError:
        return False
    return response.status_code < 500 and response.status_code not in {404, 405}


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
