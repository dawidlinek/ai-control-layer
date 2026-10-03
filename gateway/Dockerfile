# Build context: repository root (uses the workspace uv.lock, hash-pinned).
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY gateway/pyproject.toml gateway/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package acl-gateway --no-install-workspace
COPY gateway gateway
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package acl-gateway --no-editable

FROM python:3.12-slim-bookworm
RUN useradd --system --uid 10001 --home /app acl && mkdir -p /data/audit && chown acl /data/audit
WORKDIR /app
COPY --from=build --chown=acl /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 ACL_POLICY_DIR=/policy ACL_AUDIT_PATH=/data/audit/audit.jsonl
USER acl
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"
CMD ["sh", "-c", "python -m acl.migrate && exec uvicorn acl.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
