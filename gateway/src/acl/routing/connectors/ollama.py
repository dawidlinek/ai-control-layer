"""Ollama native API (`/api/chat`, `/api/embed`).

The native API reports `eval_duration` / `prompt_eval_duration` (nanoseconds), which is what meters
GPU-seconds for local models (concept §8). Responses are converted to the OpenAI shape.
`base_url` is the server root (e.g. `http://gpu-box:11434`), without `/v1`.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx

from acl.routing.connectors.base import Connector, ConnectorError, UpstreamChunk, UpstreamResponse, UpstreamUsage
from acl.routing.connectors.openai_compatible import error_from_status, transport_error

_OPTION_MAP = {
    "temperature": "temperature",
    "top_p": "top_p",
    "seed": "seed",
    "frequency_penalty": "frequency_penalty",
    "presence_penalty": "presence_penalty",
    "max_tokens": "num_predict",
    "max_completion_tokens": "num_predict",
}
_FINISH = {"stop": "stop", "length": "length", "load": "stop", "unload": "stop"}


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type", "text") == "text")
    return ""


def _args_to_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        val = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return val if isinstance(val, dict) else {}


def to_ollama_request(upstream_model: str, request: dict[str, Any], *, stream: bool) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    for m in request.get("messages") or []:
        out: dict[str, Any] = {
            "role": "system" if m.get("role") == "developer" else m.get("role"),
            "content": _text(m.get("content")),
        }
        if m.get("tool_calls"):
            out["tool_calls"] = [
                {
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": _args_to_dict(tc["function"].get("arguments")),
                    }
                }
                for tc in m["tool_calls"]
            ]
        if m.get("role") == "tool" and m.get("name"):
            out["tool_name"] = m["name"]
        messages.append(out)
    options = {dst: request[src] for src, dst in _OPTION_MAP.items() if request.get(src) is not None}
    stop = request.get("stop")
    if stop:
        options["stop"] = [stop] if isinstance(stop, str) else list(stop)
    body: dict[str, Any] = {"model": upstream_model, "messages": messages, "stream": stream}
    if options:
        body["options"] = options
    if request.get("tools"):
        body["tools"] = request["tools"]
    fmt = request.get("response_format")
    if isinstance(fmt, dict) and fmt.get("type") in ("json_object", "json_schema"):
        body["format"] = (fmt.get("json_schema") or {}).get("schema") or "json"
    return body


def _usage(data: dict[str, Any], upstream_ms: float) -> UpstreamUsage:
    gpu_ns = int(data.get("eval_duration") or 0) + int(data.get("prompt_eval_duration") or 0)
    return UpstreamUsage(
        input_tokens=int(data.get("prompt_eval_count") or 0),
        output_tokens=int(data.get("eval_count") or 0),
        gpu_seconds=gpu_ns / 1e9 if gpu_ns else None,
        upstream_ms=upstream_ms,
    )


def _openai_tool_calls(calls: list[dict[str, Any]], *, with_index: bool = False) -> list[dict[str, Any]]:
    out = []
    for i, tc in enumerate(calls):
        fn = tc.get("function") or {}
        item = {
            "id": tc.get("id") or f"call_{uuid.uuid4().hex[:12]}",
            "type": "function",
            "function": {"name": fn.get("name", ""), "arguments": json.dumps(fn.get("arguments") or {})},
        }
        if with_index:
            item["index"] = i
        out.append(item)
    return out


class OllamaConnector(Connector):
    def __init__(
        self,
        connector_id: str,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_s: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(connector_id)
        self.base_url = base_url.rstrip("/").removesuffix("/v1")
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(timeout_s, connect=min(10.0, timeout_s)))

    async def _post(self, path: str, payload: dict[str, Any]) -> tuple[dict[str, Any], float]:
        t0 = time.perf_counter()
        try:
            resp = await self._client.post(f"{self.base_url}{path}", json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise transport_error(exc) from exc
        ms = (time.perf_counter() - t0) * 1000
        if resp.status_code >= 400:
            raise error_from_status(resp.status_code, resp.content)
        try:
            return resp.json(), ms
        except ValueError as exc:
            raise ConnectorError("upstream returned invalid JSON", status=502, retryable=True) from exc

    async def chat(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        data, ms = await self._post("/api/chat", to_ollama_request(upstream_model, request, stream=False))
        msg = data.get("message") or {}
        message: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or None}
        calls = _openai_tool_calls(msg.get("tool_calls") or [])
        if calls:
            message["tool_calls"] = calls
        if msg.get("thinking"):
            message["reasoning_content"] = msg["thinking"]
        usage = _usage(data, ms)
        body = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:16]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": data.get("model", upstream_model),
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls" if calls else _FINISH.get(data.get("done_reason") or "stop", "stop"),
                }
            ],
            "usage": {
                "prompt_tokens": usage.input_tokens,
                "completion_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
            },
        }
        return UpstreamResponse(body=body, usage=usage)

    async def chat_stream(self, upstream_model: str, request: dict[str, Any]) -> AsyncIterator[UpstreamChunk]:
        payload = to_ollama_request(upstream_model, request, stream=True)
        cid, created = f"chatcmpl-{uuid.uuid4().hex[:16]}", int(time.time())
        t0 = time.perf_counter()

        def chunk(delta: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
            return {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": upstream_model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }

        yield UpstreamChunk(chunk({"role": "assistant"}))
        saw_tool_calls = False
        try:
            async with self._client.stream(
                "POST", f"{self.base_url}/api/chat", json=payload, headers=self._headers
            ) as resp:
                if resp.status_code >= 400:
                    raise error_from_status(resp.status_code, await resp.aread())
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                    except ValueError:
                        continue
                    if data.get("error"):
                        raise ConnectorError(f"upstream stream error: {str(data['error'])[:200]}", status=502)
                    msg = data.get("message") or {}
                    if msg.get("content"):
                        yield UpstreamChunk(chunk({"content": msg["content"]}))
                    if msg.get("thinking"):
                        yield UpstreamChunk(chunk({"reasoning_content": msg["thinking"]}))
                    if msg.get("tool_calls"):
                        saw_tool_calls = True
                        yield UpstreamChunk(
                            chunk({"tool_calls": _openai_tool_calls(msg["tool_calls"], with_index=True)})
                        )
                    if data.get("done"):
                        usage = _usage(data, (time.perf_counter() - t0) * 1000)
                        finish = (
                            "tool_calls" if saw_tool_calls else _FINISH.get(data.get("done_reason") or "stop", "stop")
                        )
                        last = chunk({}, finish)
                        last["usage"] = {
                            "prompt_tokens": usage.input_tokens,
                            "completion_tokens": usage.output_tokens,
                            "total_tokens": usage.input_tokens + usage.output_tokens,
                        }
                        yield UpstreamChunk(last, usage=usage)
                        return
        except httpx.HTTPError as exc:
            raise transport_error(exc) from exc

    async def embeddings(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        raw = request.get("input", [])
        inputs = [raw] if isinstance(raw, str) else list(raw)
        data, ms = await self._post("/api/embed", {"model": upstream_model, "input": inputs})
        vectors = data.get("embeddings") or []
        tokens = int(data.get("prompt_eval_count") or 0)
        body = {
            "object": "list",
            "data": [{"object": "embedding", "index": i, "embedding": v} for i, v in enumerate(vectors)],
            "model": upstream_model,
            "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
        }
        gpu_ns = int(data.get("total_duration") or 0)
        return UpstreamResponse(
            body=body,
            usage=UpstreamUsage(input_tokens=tokens, gpu_seconds=gpu_ns / 1e9 if gpu_ns else None, upstream_ms=ms),
        )

    async def health(self) -> bool:
        try:
            resp = await self._client.get(f"{self.base_url}/api/tags", headers=self._headers, timeout=3.0)
        except httpx.HTTPError:
            return False
        return resp.status_code < 500

    async def aclose(self) -> None:
        await self._client.aclose()
