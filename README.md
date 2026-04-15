# langgraph-secure-gateway

Reusable security gateway package for LangGraph applications.

## CLI

- `secure-langgraph build`: wrapper around `langgraph build` with safe defaults
- `secure-langgraph init-deploy`: generate deploy files for a new LangGraph repo
- `secure-langgraph create-admin-user`: bootstrap or rotate admin credentials
- `secure-langgraph init-db`: create auth tables in Postgres
- `secure-langgraph reset-db`: drop and recreate auth schema (destructive)

## Gateway entrypoint

Run with uvicorn:

```bash
uvicorn langgraph_secure_gateway.entrypoints:app --host 0.0.0.0 --port 8000
```

Set `AUTH_DB_AUTO_INIT=true` to auto-create auth tables on gateway startup.

## Development

Install dev dependencies:

```bash
uv sync --group dev
```

Run the gateway in reload mode with FastAPI CLI:

```bash
uv run --group dev fastapi dev src/langgraph_secure_gateway/entrypoints.py
```

Useful local routes:

- Gateway docs: `http://127.0.0.1:8000/gateway/docs`
- Gateway OpenAPI: `http://127.0.0.1:8000/gateway/openapi.json`
- Health check: `http://127.0.0.1:8000/healthz`

## JWT identity

The gateway issues and verifies Bearer JWT tokens locally.

Required environment variables:

- `JWT_SECRET`

Optional environment variables:

- `JWT_ALGORITHM` (default: `HS256`)
- `JWT_EXPIRE_MINUTES` (default: `60`)

Runtime behavior:

- Clients get a token from `POST /auth/login`.
- Every non-public request must provide `Authorization: Bearer <token>`.
- The token `sub` is a UUID and must match an active user in DB.
- Gateway forwards `x-authenticated-user-id` (UUID) and `x-authenticated-user` upstream.

## Reset database (destructive)

Use this when rolling out schema-breaking changes (for example, switching user IDs to UUID):

```bash
uv run secure-langgraph reset-db --yes
```

Warning: this drops and recreates the entire `public` schema in Postgres.

On Coolify, run the same command inside the gateway service/container where `POSTGRES_URI` is set.

## API documentation

- Gateway docs (this app): `/gateway/docs`
- Gateway OpenAPI JSON (this app): `/gateway/openapi.json`
- Upstream LangGraph docs (proxied): `/docs`
- Upstream OpenAPI JSON (proxied): `/openapi.json`
