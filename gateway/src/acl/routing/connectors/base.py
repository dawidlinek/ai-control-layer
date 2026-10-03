"""Upstream connector interface. Connectors speak OpenAI-shaped dicts in and out.

Implementations: `mock` (deterministic, tests), `openai_compatible` (vLLM, SGLang, Ollama /v1,
Gemini), `ollama` (native API, gives eval_duration timings for GPU-second metering).
Credentials are resolved from the gateway environment only (`env:NAME` in policy).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any


class ConnectorError(Exception):
    def __init__(self, message: str, *, status: int = 502, retryable: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable


@dataclass
class UpstreamUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    gpu_seconds: float | None = None  # from upstream timings when available
    upstream_ms: float = 0.0


@dataclass
class UpstreamResponse:
    """A complete (non-streaming) chat completion in OpenAI format plus metering."""

    body: dict[str, Any]
    usage: UpstreamUsage = field(default_factory=UpstreamUsage)


@dataclass
class UpstreamChunk:
    """One streaming chunk (OpenAI `chat.completion.chunk` dict). `usage` set on the last chunk."""

    body: dict[str, Any]
    usage: UpstreamUsage | None = None


class Connector(ABC):
    def __init__(self, connector_id: str) -> None:
        self.id = connector_id

    @abstractmethod
    async def chat(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse: ...

    @abstractmethod
    def chat_stream(self, upstream_model: str, request: dict[str, Any]) -> AsyncIterator[UpstreamChunk]: ...

    @abstractmethod
    async def embeddings(self, upstream_model: str, request: dict[str, Any]) -> UpstreamResponse: ...

    async def health(self) -> bool:
        return True

    async def aclose(self) -> None:  # noqa: B027 - optional hook
        pass
