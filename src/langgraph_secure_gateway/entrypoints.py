"""ASGI entrypoints for framework-driven runners."""

from langgraph_secure_gateway.app import create_gateway_app

app = create_gateway_app()

__all__ = ["app"]
