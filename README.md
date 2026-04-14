# langgraph-secure-gateway

Reusable security gateway package for LangGraph applications.

## CLI

- `secure-langgraph build`: wrapper around `langgraph build` with safe defaults
- `secure-langgraph init-deploy`: generate deploy files for a new LangGraph repo
- `secure-langgraph create-admin-user`: bootstrap or rotate admin credentials

## Gateway entrypoint

Run with uvicorn:

```bash
uvicorn langgraph_secure_gateway.entrypoints:app --host 0.0.0.0 --port 8000
```
