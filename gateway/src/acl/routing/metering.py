"""Usage metering: tokens, USD (model pricing) and GPU-seconds (upstream timings or estimate)."""

from __future__ import annotations

import math

from acl.contracts.audit import Usage
from acl.policy.models import ModelEntry
from acl.routing.connectors.base import UpstreamUsage


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / 4) if text else 0


def compute_usage(model: ModelEntry | None, up: UpstreamUsage) -> Usage:
    """Audit `Usage` for one upstream call.

    GPU-seconds come from the upstream when it reports timings (Ollama), else from the model's
    `gpu_seconds_per_1k_tokens` estimate (vLLM/SGLang). USD = token prices + GPU-seconds × $/GPU-second.
    """
    gpu = up.gpu_seconds
    pricing = model.pricing if model else None
    if gpu is None:
        per_1k = pricing.gpu_seconds_per_1k_tokens if pricing else None
        gpu = (up.input_tokens + up.output_tokens) / 1000.0 * per_1k if per_1k else 0.0
    usd = 0.0
    if pricing:
        usd = (
            up.input_tokens / 1000.0 * pricing.in_per_1k
            + up.output_tokens / 1000.0 * pricing.out_per_1k
            + gpu * pricing.usd_per_gpu_second
        )
    return Usage(
        input_tokens=up.input_tokens,
        output_tokens=up.output_tokens,
        reasoning_tokens=up.reasoning_tokens,
        usd=round(usd, 8),
        gpu_seconds=round(gpu, 6),
    )
