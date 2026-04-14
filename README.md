# langgraph-secure-gateway

Reusable security gateway package for LangGraph applications.

## CLI

- `secure-langgraph build`: wrapper around `langgraph build` with safe defaults
- `secure-langgraph init-deploy`: generate deploy files for a new LangGraph repo
- `secure-langgraph create-admin-user`: bootstrap or rotate admin credentials
- `secure-langgraph init-db`: create auth tables in Postgres

## Gateway entrypoint

Run with uvicorn:

```bash
uvicorn langgraph_secure_gateway.entrypoints:app --host 0.0.0.0 --port 8000
```

Set `AUTH_DB_AUTO_INIT=true` to auto-create auth tables on gateway startup.

## API documentation

- Gateway docs (this app): `/gateway/docs`
- Gateway OpenAPI JSON (this app): `/gateway/openapi.json`
- Upstream LangGraph docs (proxied): `/docs`
- Upstream OpenAPI JSON (proxied): `/openapi.json`
