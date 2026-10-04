"""The pipeline's input record: one redacted prompt plus metadata. Never holds raw text or vault entries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from acl.contracts.common import DataClass


@dataclass(frozen=True)
class PromptRecord:
    key: str  # audit event id (or seed id)
    subject: str  # principal subject: counted for k, used for personal ownership, never returned by the API
    groups: tuple[str, ...]
    timestamp: datetime
    session_id: str | None
    text: str  # redacted / pseudonymised text as stored in the audit index
    model: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0
    gpu_seconds: float = 0.0
    latency_ms: float = 0.0
    data_class: DataClass = DataClass.internal
    tools: tuple[str, ...] = field(default_factory=tuple)
    source: Literal["audit", "seed"] = "audit"
