FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system gateway && useradd --system --gid gateway gateway

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts

RUN pip install --no-cache-dir . && \
    pip uninstall -y pip setuptools wheel && \
    rm -rf /root/.cache

USER gateway

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "langgraph_secure_gateway.entrypoints:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
