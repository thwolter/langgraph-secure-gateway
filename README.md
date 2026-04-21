# langgraph-secure-gateway

Standalone FastAPI backend for authenticating users, managing LangGraph agent
access, and proxying authorized frontend traffic to private LangGraph services.

The frontend logs in through this gateway. After login, `GET /auth/session`
returns only the agents available to the authenticated user. Each returned agent
has a gateway URL plus the configured `assistant_id` and/or `graph_id`.

## Runtime Model

```text
frontend
  |
  v
gateway backend
  |-- Postgres: users, admins, agents, access grants
  |-- private LangGraph API A
  |-- private LangGraph API B
  |-- private LangGraph API C
```

LangGraph services should not be exposed directly to the browser. The frontend
uses the gateway-scoped agent URLs returned by `/auth/session`, for example:

```text
https://gateway.example.com/agents/research-agent
```

The gateway verifies the bearer token, checks the user's grant for
`research-agent`, and proxies the request to that agent's configured private
`base_url`.

## Configuration

Copy `example.env` to `.env` for Docker Compose usage and replace all secrets.

Required environment variables:

- `POSTGRES_URI`: Postgres connection URI when running without Compose
- `JWT_SECRET`: signing secret for frontend bearer tokens
- `ADMIN_SESSION_SECRET`: signing secret for the admin UI session cookie

Optional environment variables:

- `JWT_ALGORITHM`: default `HS256`
- `JWT_EXPIRE_MINUTES`: default `60`
- `AUTH_DB_AUTO_MIGRATE`: run Alembic migrations on startup, default `false`
- `CORS_ORIGINS`: comma-separated browser origins, for example
  `https://app.example.com,http://localhost:5173`

## Coolify Deployment

The default `docker-compose.yaml` is Coolify-first. It attaches the gateway to:

- the default project network for Postgres
- `gateway-net` for private LangGraph services
- `coolify` for the Coolify reverse proxy

Set `GATEWAY_NETWORK_NAME` to the same external Docker network used by the
LangGraph server compose file. The default is `gateway-net`. The default Coolify
proxy network name is `coolify`; override it with `COOLIFY_PROXY_NETWORK_NAME`
if your Coolify installation uses a different name.

The gateway service exposes container port `8000` to the Coolify proxy network;
it does not publish a host port in the Coolify compose.

The Agent admin form can discover LangGraph APIs from `LANGGRAPH_DISCOVERY_URLS`,
a comma-separated list such as `http://langgraph-api:8000`. If the gateway
container has access to `/var/run/docker.sock`, it can also inspect
`GATEWAY_NETWORK_NAME` and list LangGraph containers that respond to
`/assistants/search`.

Create the first admin user:

```bash
docker compose --env-file .env -f docker-compose.coolify.yaml exec gateway \
  secure-langgraph create-admin-user \
  --email admin@example.com \
  --first-name Admin \
  --last-name User \
  --password 'change-me'
```

Open the admin panel. The service root redirects here too:

```text
https://gateway.example.com/admin/
```

In the admin panel:

1. Create users.
2. Create agents with `key`, `name`, private `base_url`, and optional
   `assistant_id` or `graph_id`.
3. Create `User Agent Access` grants to assign agents to users.

## Local Development

Build and run the standalone gateway with Postgres:

```bash
cp example.env .env
docker compose --env-file .env -f docker-compose.yaml up --build
```

The local gateway listens on `http://127.0.0.1:8000` by default.
The local compose creates `gateway-net` instead of requiring it to already
exist.

Install dependencies:

```bash
uv sync --group dev
```

Run migrations:

```bash
POSTGRES_URI='postgres://gateway:gateway@localhost:5432/gateway?sslmode=disable' \
  uv run secure-langgraph init-db
```

Run the gateway:

```bash
uv run --group dev fastapi dev src/langgraph_secure_gateway/entrypoints.py
```

Useful routes:

- Health check: `GET /healthz`
- Service root: `GET /` redirects to `/admin/`
- Gateway docs: `GET /gateway/docs`
- Admin panel: `GET /admin/`

## Frontend Auth Flow

Login:

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "change-me"
}
```

Response:

```json
{
  "access_token": "jwt",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Load the authenticated session:

```http
GET /auth/session
Authorization: Bearer jwt
```

Response:

```json
{
  "user": {
    "id": "00000000-0000-0000-0000-000000000000",
    "email": "user@example.com",
    "first_name": "User",
    "last_name": "Example",
    "is_admin": false
  },
  "agents": [
    {
      "id": "11111111-1111-1111-1111-111111111111",
      "key": "research-agent",
      "name": "Research Agent",
      "description": "General research assistant",
      "url": "https://gateway.example.com/agents/research-agent",
      "assistant_id": "assistant-id",
      "graph_id": "agent"
    }
  ]
}
```

Use the returned `url` for LangGraph calls:

```http
POST /agents/research-agent/runs/stream
Authorization: Bearer jwt
Content-Type: application/json

{
  "assistant_id": "assistant-id",
  "input": {
    "messages": [
      {
        "role": "user",
        "content": "Hello"
      }
    ]
  }
}
```

The gateway injects the authenticated UUID into supported LangGraph request
bodies:

- `POST /agents/{key}/threads`: sets `metadata.owner`
- `POST /agents/{key}/threads/search`: restricts non-admin users to their owner
  metadata
- run create endpoints: sets `config.configurable.user_id`

Forwarded identity headers:

- `x-authenticated-user-id`
- `x-authenticated-user-email`
- `x-authenticated-user-first-name`
- `x-authenticated-user-last-name`

The gateway does not forward the frontend `Authorization` header to upstream
LangGraph services.

## CLI

List commands:

```bash
uv run secure-langgraph --help
```

Common commands:

```bash
uv run secure-langgraph init-db

uv run secure-langgraph create-admin-user \
  --email admin@example.com \
  --password 'change-me'

uv run secure-langgraph reset-db --yes
```

## LangGraph Auth Handler

If a proxied LangGraph app uses LangGraph SDK auth, configure it to trust the
gateway's injected identity headers. The deploy helper can generate an `auth.py`
for LangGraph projects:

```bash
uv run secure-langgraph init-deploy --cwd /path/to/langgraph-app
```

The generated handler expects `x-authenticated-user-id` and uses
`x-authenticated-user-email` as the display name when available.

## Code Quality

```bash
uv run --group dev ruff check .
uv run --group dev ruff format .
uv run --group dev isort .
uv run --group dev ssort --check src scripts
uv run --group dev pyrefly check src
```
