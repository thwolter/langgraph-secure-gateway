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
      - ./docker/postgres/init:/docker-entrypoint-initdb.d:ro
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
    ports:
      - \"{public_port}:8000\"
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
      LANGGRAPH_UPSTREAM_URL: http://langgraph-api:8000
"""

ENV_EXAMPLE_TEMPLATE = """OPENAI_API_KEY=
LANGSMITH_API_KEY=
JWT_SECRET=
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
ADMIN_SESSION_SECRET=
"""

AUTH_SQL_TEMPLATE = """CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS panel_access (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  panel_key VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_user_panel UNIQUE (user_id, panel_key)
);

CREATE INDEX IF NOT EXISTS idx_panel_access_user_id ON panel_access(user_id);
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


def write_if_missing(path: Path, content: str, *, force: bool) -> bool:
    """Write file if missing or force is enabled."""
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True
