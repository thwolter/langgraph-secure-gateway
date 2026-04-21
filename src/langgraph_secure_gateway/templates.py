"""Template rendering for deploy bootstrap files."""

from __future__ import annotations

from pathlib import Path

COMPOSE_TEMPLATE = """volumes:
  langgraph-data:
    driver: local
services:
  langgraph-redis:
    image: redis:6
    healthcheck:
      test: redis-cli ping
      interval: 5s
      timeout: 1s
      retries: 5
  langgraph-postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: postgres
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - langgraph-data:/var/lib/postgresql/data
    healthcheck:
      test: pg_isready -U postgres
      start_period: 10s
      timeout: 1s
      retries: 5
      interval: 5s
  langgraph-api:
    pull_policy: never
    build:
      context: .
      dockerfile: Dockerfile
    image: \"{image_tag}\"
    depends_on:
      langgraph-redis:
        condition: service_healthy
      langgraph-postgres:
        condition: service_healthy
    environment:
      FORWARDED_ALLOW_IPS: \"*\"
      REDIS_URI: redis://langgraph-redis:6379
      POSTGRES_URI: postgres://postgres:postgres@langgraph-postgres:5432/postgres?sslmode=disable
      LANGSMITH_API_KEY: ${{LANGSMITH_API_KEY}}
      OPENAI_API_KEY: ${{OPENAI_API_KEY}}
  auth-gateway:
    pull_policy: never
    image: \"{image_tag}\"
    entrypoint: [\"python\", \"-m\", \"uvicorn\", \"langgraph_secure_gateway.entrypoints:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]
    expose:
      - \"8000\"
    depends_on:
      langgraph-api:
        condition: service_started
      langgraph-postgres:
        condition: service_healthy
    environment:
      POSTGRES_URI: postgres://postgres:postgres@langgraph-postgres:5432/postgres?sslmode=disable
      JWT_SECRET: ${{JWT_SECRET}}
      JWT_ALGORITHM: ${{JWT_ALGORITHM:-HS256}}
      JWT_EXPIRE_MINUTES: ${{JWT_EXPIRE_MINUTES:-60}}
      ADMIN_SESSION_SECRET: ${{ADMIN_SESSION_SECRET}}
      AUTH_DB_AUTO_MIGRATE: ${{AUTH_DB_AUTO_MIGRATE:-true}}
      CORS_ORIGINS: ${{CORS_ORIGINS:-}}
"""

ENV_EXAMPLE_TEMPLATE = """OPENAI_API_KEY=
LANGSMITH_API_KEY=
JWT_SECRET=
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
ADMIN_SESSION_SECRET=
AUTH_DB_AUTO_MIGRATE=true
CORS_ORIGINS=
"""

DOCKERFILE_TEMPLATE = """FROM langchain/langgraph-api:3.11-wolfi

ADD . /deps/app

RUN for dep in /deps/*; do \\
  if [ -d \"$dep\" ]; then \\
    (cd \"$dep\" && PYTHONDONTWRITEBYTECODE=1 uv pip install --system --no-cache-dir -c /api/constraints.txt -e .); \\
  fi; \\
 done

ENV LANGSERVE_GRAPHS='{"agent": "/deps/app/src/agent/graph.py:graph"}'

RUN mkdir -p /api/langgraph_api /api/langgraph_runtime /api/langgraph_license && \\
  touch /api/langgraph_api/__init__.py /api/langgraph_runtime/__init__.py /api/langgraph_license/__init__.py
RUN PYTHONDONTWRITEBYTECODE=1 uv pip install --system --no-cache-dir --no-deps -e /api

RUN pip uninstall -y pip setuptools wheel
RUN rm -rf /usr/local/lib/python*/site-packages/pip* /usr/local/lib/python*/site-packages/setuptools* /usr/local/lib/python*/site-packages/wheel* && \\
  find /usr/local/bin -name \"pip*\" -delete || true
RUN rm -rf /usr/lib/python*/site-packages/pip* /usr/lib/python*/site-packages/setuptools* /usr/lib/python*/site-packages/wheel* && \\
  find /usr/bin -name \"pip*\" -delete || true
RUN uv pip uninstall --system pip setuptools wheel && rm /usr/bin/uv /usr/bin/uvx

WORKDIR /deps/app
"""

LANGGRAPH_AUTH_TEMPLATE = """\"\"\"LangGraph auth handlers that trust the upstream gateway headers.\"\"\"

from __future__ import annotations

from typing import Any

from langgraph_sdk import Auth

my_auth = Auth()


def _get_text_header(headers: dict[bytes, bytes], name: str) -> str | None:
    value = headers.get(name.encode('utf-8'))
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode('utf-8').strip()
    else:
        text = str(value).strip()
    return text or None


@my_auth.authenticate
async def authenticate(headers: dict[bytes, bytes]) -> Auth.types.MinimalUserDict:
    \"\"\"Authenticate a request based on gateway-injected identity headers.\"\"\"
    user_id = _get_text_header(headers, 'x-authenticated-user-id')
    email = _get_text_header(headers, 'x-authenticated-user-email')
    if user_id is None:
        raise Auth.exceptions.HTTPException(
            status_code=401,
            detail='Missing authenticated identity headers',
        )

    user: Auth.types.MinimalUserDict = {'identity': user_id, 'is_authenticated': True}
    if email is not None:
        user['display_name'] = email
    return user


@my_auth.on
async def enforce_owner_scope(
    ctx: Auth.types.AuthContext, value: dict[str, Any]
) -> Auth.types.FilterType:
    \"\"\"Persist owner metadata and restrict access to owner-scoped resources.\"\"\"
    filters = {'owner': ctx.user.identity}
    metadata = value.setdefault('metadata', {})
    if isinstance(metadata, dict):
        metadata.update(filters)
    return filters
"""


def write_if_missing(path: Path, content: str, *, force: bool) -> bool:
    """Write file if missing or force is enabled."""
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    return True
