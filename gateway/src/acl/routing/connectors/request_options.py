"""Per-model upstream request options from policy (`ModelEntry.request_defaults`, `reasoning_headroom_tokens`).

Reasoning models (Gemini 2.5/3 behind the OpenAI-compatible endpoint, ...) spend hidden thinking tokens out of the
same `max_tokens` budget as the visible answer, so a client asking for 400 tokens can get one sentence and
`finish_reason: length`. Policy fixes that per model: default `reasoning_effort`, and extra headroom on the cap.
Applied per route at call time, so a failover to another model never inherits the first model's options.
"""

from __future__ import annotations

import copy
from typing import Any

from acl.policy.models import ModelEntry

TOKEN_CAP_KEYS = ("max_tokens", "max_completion_tokens")


def with_model_options(request: dict[str, Any], model: ModelEntry) -> dict[str, Any]:
    """Copy of `request` with the model's defaults filled in (client values win) and the token cap raised."""
    if not model.request_defaults and not model.reasoning_headroom_tokens:
        return request
    out = dict(request)
    for key, value in model.request_defaults.items():
        out.setdefault(key, copy.deepcopy(value))
    if model.reasoning_headroom_tokens:
        for key in TOKEN_CAP_KEYS:
            value = out.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                out[key] = value + model.reasoning_headroom_tokens
    return out
