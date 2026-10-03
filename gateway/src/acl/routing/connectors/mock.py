"""Deterministic mock LLM connector (tests, demo without a model server).

Default behaviour: echo the last user message as `MOCK[<model>]: <text>`.
Directives in the last user (or tool) message script the output:

    [[mock:reply <text>]]                 reply with exactly <text>
    [[mock:tool <name> <json-args>]]      emit one tool_call (args must be single-line JSON)
    [[mock:repeat <n> <text>]]            reply with <text> repeated n times (endless-generation tests)
    [[mock:reasoning <text>]]             attach a reasoning trace and logprobs (egress-hygiene tests)
    [[mock:error <status>]]               raise ConnectorError(status)
    [[mock:tokens <n>]]                   report n output tokens regardless of text

Token counts are ceil(chars / 4); GPU-seconds = output_tokens * 0.001 (deterministic).
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import AsyncIterator
from typing import Any

from acl.routing.connectors.base import Connector, ConnectorError, UpstreamChunk, UpstreamResponse, UpstreamUsage

_DIRECTIVE = re.compile(r"\[\[mock:(?P<cmd>[a-z]+)(?:\s+(?P<arg>.*?))?\]\]", re.S)
CHUNK_CHARS = 16


def _tokens(text: str) -> int:
    return math.ceil(len(text) / 4) if text else 0


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


class MockConnector(Connector):
    def __init__(self, connector_id: str = "mock") -> None:
        super().__init__(connector_id)
        self.calls: list[dict[str, Any]] = []

    def _plan(self, upstream_model: str, request: dict[str, Any]) -> tuple[dict[str, Any], UpstreamUsage]:
        self.calls.append({"model": upstream_model, "request": request})
        messages = request.get("messages") or []
        prompt_text = "".join(_text_of(m.get("content")) for m in messages)
        last = next((m for m in reversed(messages) if m.get("role") in ("user", "tool")), None)
        last_text = _text_of(last.get("content")) if last else ""

        content: str | None = f"MOCK[{upstream_model}]: {_DIRECTIVE.sub('', last_text).strip()}"
        tool_calls: list[dict[str, Any]] = []
        message_extra: dict[str, Any] = {}
        choice_extra: dict[str, Any] = {}
        forced_tokens: int | None = None

        for m in _DIRECTIVE.finditer(last_text):
            cmd, arg = m.group("cmd"), (m.group("arg") or "").strip()
            if cmd == "reply":
                content = arg
            elif cmd == "tool":
                name, _, raw_args = arg.partition(" ")
                json.loads(raw_args or "{}")  # validate early: tests should fail loudly on bad JSON
                tool_calls.append(
                    {
                        "id": f"call_{len(tool_calls)}",
                        "type": "function",
                        "function": {"name": name, "arguments": raw_args or "{}"},
                    }
                )
                content = None
            elif cmd == "repeat":
                n, _, text = arg.partition(" ")
                content = text * int(n)
            elif cmd == "reasoning":
                message_extra["reasoning_content"] = arg
                choice_extra["logprobs"] = {"content": [{"token": "x", "logprob": -0.1}]}
            elif cmd == "error":
                raise ConnectorError(f"mock upstream error {arg}", status=int(arg or 502))
            elif cmd == "tokens":
                forced_tokens = int(arg)

        message: dict[str, Any] = {"role": "assistant", "content": content, **message_extra}
        if tool_calls:
            message["tool_calls"] = tool_calls
        out_tokens = forced_tokens if forced_tokens is not None else _tokens(content or json.dumps(tool_calls))
        usage = UpstreamUsage(
            input_tokens=_tokens(prompt_text),
            output_tokens=out_tokens,
            gpu_seconds=out_tokens * 0.001,
            upstream_ms=1.0,
        )
        body = {
            "id": f"chatcmpl-mock-{len(self.calls)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": upstream_model,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls" if tool_calls else "stop",
                    **choice_extra,
                }
            ],
            "usage": {
                "prompt_tokens": usage.input_tokens,
                "completion_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
            },
        }
        return body, usage

    async def chat(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        body, usage = self._plan(upstream_model, request)
        return UpstreamResponse(body=body, usage=usage)

    async def chat_stream(self, upstream_model: str, request: dict[str, Any]) -> AsyncIterator[UpstreamChunk]:
        body, usage = self._plan(upstream_model, request)
        choice = body["choices"][0]
        msg = choice["message"]
        base = {"id": body["id"], "object": "chat.completion.chunk", "created": body["created"], "model": body["model"]}
        yield UpstreamChunk({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]})
        text = msg.get("content") or ""
        for i in range(0, len(text), CHUNK_CHARS):
            delta = {"content": text[i : i + CHUNK_CHARS]}
            yield UpstreamChunk({**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]})
        if msg.get("tool_calls"):
            calls = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
            yield UpstreamChunk(
                {**base, "choices": [{"index": 0, "delta": {"tool_calls": calls}, "finish_reason": None}]}
            )
        yield UpstreamChunk(
            {
                **base,
                "choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}],
                "usage": body["usage"],
            },
            usage=usage,
        )

    async def embeddings(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse:
        raw = request.get("input", [])
        inputs = [raw] if isinstance(raw, str) else list(raw)
        data = []
        for i, text in enumerate(inputs):
            # Deterministic 8-dim pseudo-embedding from character statistics.
            vec = [0.0] * 8
            for j, ch in enumerate(str(text)):
                vec[j % 8] += (ord(ch) % 97) / 97.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            data.append({"object": "embedding", "index": i, "embedding": [v / norm for v in vec]})
        tokens = sum(_tokens(str(t)) for t in inputs)
        body = {
            "object": "list",
            "data": data,
            "model": upstream_model,
            "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
        }
        return UpstreamResponse(body=body, usage=UpstreamUsage(input_tokens=tokens))
