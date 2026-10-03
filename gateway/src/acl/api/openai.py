"""OpenAI-compatible routes: `/v1/chat/completions`, `/v1/embeddings`, `/v1/models` (concept §4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from acl.api.chat_flow import ChatFlow, EmbeddingsFlow, models_listing
from acl.api.deps import PrincipalDep
from acl.api.errors import GatewayError

router = APIRouter(prefix="/v1", tags=["openai"])


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError as exc:
        raise GatewayError(400, "invalid_request_error", "request body must be valid JSON") from exc
    if not isinstance(body, dict):
        raise GatewayError(400, "invalid_request_error", "request body must be a JSON object")
    return body


@router.post("/chat/completions", operation_id="createChatCompletion")
async def chat_completions(request: Request, principal: PrincipalDep) -> Response:
    """Chat completion (JSON or SSE when `stream: true`), inspected at ingress and egress."""
    return await ChatFlow(request, principal).run(await _json_body(request))


@router.post("/embeddings", operation_id="createEmbedding")
async def embeddings(request: Request, principal: PrincipalDep) -> Response:
    """Embeddings; the input is treated as outbound data and inspected at the `embeddings` point."""
    return await EmbeddingsFlow(request, principal).run(await _json_body(request))


@router.get("/models", operation_id="listModels")
async def list_models(request: Request, principal: PrincipalDep) -> dict[str, Any]:
    """Personalised: only the models, aliases and skills the caller may use."""
    return await models_listing(request, principal)
