"""OpenAI-compatible upstream (vLLM, SGLang, Ollama `/v1`, Gemini's OpenAI endpoint, ...).

Credentials and the base URL are resolved by the registry from `env:NAME` references and handed in
here; this class never reads policy or the environment itself.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from acl.routing.connectors.base import Connector, ConnectorError, UpstreamChunk, UpstreamResponse, UpstreamUsage

log = logging.getLogger(__name__)


def parse_usage(raw: dict[str, Any] | None, *, upstream_ms: float = 0.0) -> UpstreamUsage:
    """OpenAI `usage` object → metering.

    Gemini (and other reasoning models) hide reasoning tokens outside `completion_tokens`; the bill
    follows `total_tokens`, so output is metered as max(completion_tokens, total_tokens - prompt_tokens).
    """
    raw = raw or {}
    prompt = int(raw.get("prompt_tokens") or 0)
    completion = int(raw.get("completion_tokens") or 0)
    total = int(raw.get("total_tokens") or 0)
    output = max(completion, total - prompt) if total else completion
    details = raw.get("completion_tokens_details") or {}
    reasoning = int(details.get("reasoning_tokens") or 0) if isinstance(details, dict) else 0
    reasoning = max(reasoning, output - completion)
    return UpstreamUsage(input_tokens=prompt, output_tokens=output, reasoning_tokens=reasoning, upstream_ms=upstream_ms)


def error_from_status(status: int, body: bytes | str) -> ConnectorError:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    detail = ""
    try:
        data = json.loads(text)
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            detail = str(err.get("message") or "")
        elif isinstance(err, str):
            detail = err
        elif isinstance(data, list) and data and isinstance(data[0], dict):  # Gemini wraps errors in a list
            detail = str((data[0].get("error") or {}).get("message") or "")
    except (ValueError, AttributeError):
        pass
    log.warning("upstream returned HTTP %s", status)
    msg = f"upstream returned HTTP {status}" + (f": {detail[:200]}" if detail else "")
    return ConnectorError(msg, status=status, retryable=status >= 500 or status == 429)


def transport_error(exc: httpx.HTTPError) -> ConnectorError:
    if isinstance(exc, httpx.TimeoutException):
        return ConnectorError("upstream timed out", status=504, retryable=True)
    return ConnectorError(f"upstream unreachable ({type(exc).__name__})", status=502, retryable=True)


class OpenAICompatibleConnector(Connector):
    def __init__(
        self,
        connector_id: str,
        base_url: str,
        *,
        api_key: str | None = None,
        headers: dict[str, str] | None = None,
        timeout_s: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(connector_id)
        self.base_url = base_url.rstrip("/")
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        if api_key:
            hdrs["Authorization"] = f"Bearer {api_key}"
        self._headers = hdrs
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(timeout_s, connect=min(10.0, timeout_s)))

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def _post_json(self, path: str, payload: dict[str, Any]) -> tuple[dict[str, Any], float]:
        t0 = time.perf_counter()
        try:
            resp = await self._client.post(self._url(path), json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise transport_error(exc) from exc
        ms = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            raise error_from_status(resp.status_code, resp.content)
        try:
            body = resp.json()
        except ValueError as exc:
            raise ConnectorError("upstream returned invalid JSON", status=502, retryable=True) from exc
        if not isinstance(body, dict):
            raise ConnectorError("upstream returned an unexpected body", status=502, retryable=True)
        return body, ms

    async def chat(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        payload = {**request, "model": upstream_model, "stream": False}
        payload.pop("stream_options", None)
        body, ms = await self._post_json("/chat/completions", payload)
        if not body.get("choices"):
            raise ConnectorError("upstream returned no choices", status=502, retryable=True)
        return UpstreamResponse(body=body, usage=parse_usage(body.get("usage"), upstream_ms=ms))

    async def chat_stream(self, upstream_model: str, request: dict[str, Any]) -> AsyncIterator[UpstreamChunk]:
        payload = {**request, "model": upstream_model, "stream": True}
        payload["stream_options"] = {**(request.get("stream_options") or {}), "include_usage": True}
        t0 = time.perf_counter()
        usage_raw: dict[str, Any] | None = None
        try:
            async with self._client.stream(
                "POST", self._url("/chat/completions"), json=payload, headers=self._headers
            ) as resp:
                if resp.status_code >= 400:
                    raise error_from_status(resp.status_code, await resp.aread())
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or line.startswith(":") or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        body = json.loads(data)
                    except ValueError:
                        log.warning("dropping malformed SSE line from %s", self.id)
                        continue
                    if not isinstance(body, dict):
                        continue
                    if isinstance(body.get("error"), dict):  # in-stream error object
                        raise ConnectorError(
                            f"upstream stream error: {str(body['error'].get('message', ''))[:200]}", status=502
                        )
                    if body.get("usage"):
                        usage_raw = body["usage"]
                        if not body.get("choices"):  # pure usage chunk: emitted last
                            continue
                        body = {**body, "usage": None}  # usage riding on a content chunk: content now, usage last
                    yield UpstreamChunk(body=body)
        except httpx.HTTPError as exc:
            raise transport_error(exc) from exc
        if usage_raw:
            ms = (time.perf_counter() - t0) * 1000
            yield UpstreamChunk(body={"choices": [], "usage": usage_raw}, usage=parse_usage(usage_raw, upstream_ms=ms))

    async def embeddings(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        body, ms = await self._post_json("/embeddings", {**request, "model": upstream_model})
        usage = parse_usage(body.get("usage"), upstream_ms=ms)
        usage.input_tokens = usage.input_tokens or int((body.get("usage") or {}).get("total_tokens") or 0)
        usage.output_tokens = 0
        return UpstreamResponse(body=body, usage=usage)

    async def health(self) -> bool:
        try:
            resp = await self._client.get(self._url("/models"), headers=self._headers, timeout=3.0)
        except httpx.HTTPError:
            return False
        return resp.status_code < 500

    async def aclose(self) -> None:
        await self._client.aclose()
