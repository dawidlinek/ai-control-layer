# Demo MCP servers. Build context: repository root (uses the workspace uv.lock, hash-pinned).
#   docker build -f mcp-servers/Dockerfile --build-arg SERVER=core-banking .
# One image recipe for every server: SERVER is the directory under mcp-servers/ (server.py inside).
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY gateway/pyproject.toml gateway/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package acl-gateway --no-install-workspace

FROM python:3.12-slim-bookworm
ARG SERVER
RUN test -n "$SERVER" && useradd --system --uid 10003 --home /srv mcp
WORKDIR /srv
COPY --from=build --chown=mcp /app/.venv /app/.venv
COPY --chown=mcp mcp-servers/common.py ./common.py
COPY --chown=mcp mcp-servers/${SERVER} ./${SERVER}
# governed-tools lists/reads the same demo workspace as the files server
COPY --chown=mcp mcp-servers/files/workspace ./files/workspace
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 PORT=8000 SERVER=${SERVER}
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"
CMD ["sh", "-c", "exec python /srv/${SERVER}/server.py"]
