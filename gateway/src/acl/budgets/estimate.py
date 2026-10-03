"""Pre-dispatch estimates (concept §8: "estimate the input tokens and the maximum output, check every budget").

Input tokens come from the inspected payload text (ceil(chars / 4), the same estimator the flow uses when an
upstream reports no usage); output is the requested `max_tokens` capped by `budgets.stream.max_output_tokens`
(and the model's own cap), or that cap itself when the client asked for none (worst case). USD / GPU-seconds
use the pricing of the model the name resolves to; a name that only the router can resolve (`auto`) is priced
as the local target (the cheapest outcome), and cumulative exhaustion is checked separately from the estimate.
"""

from __future__ import annotations

from dataclasses import dataclass

from acl.contracts.inspection import ChatPayload, EmbeddingsPayload, InspectionContext, Payload
from acl.engine.text import iter_texts
from acl.policy.models import ModelEntry, Policy
from acl.routing.connectors.base import UpstreamUsage
from acl.routing.metering import compute_usage, estimate_tokens


@dataclass(frozen=True)
class Estimate:
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    gpu_seconds: float = 0.0
    tool_calls: int = 0

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


ZERO = Estimate()


def resolve_model(policy: Policy, name: str | None) -> ModelEntry | None:
    """Concrete model for a requested name (id, model alias, `fixed` alias, skill); None for auto/unknown."""
    if not name:
        return None
    models = policy.model_by_id()
    skill = policy.skills.get(name)
    if skill is not None:
        name = skill.model
    if name in models:
        return models[name]
    for m in policy.models:
        if name in m.aliases:
            return m
    alias = policy.aliases.get(name)
    if alias is not None and alias.strategy == "fixed" and alias.target in models:
        return models[alias.target]
    return None


def input_tokens_of(payload: Payload) -> int:
    if isinstance(payload, ChatPayload | EmbeddingsPayload):
        return estimate_tokens("\n".join(text for _, text in iter_texts(payload)))  # same estimator as the flow
    return 0


def requested_output(payload: Payload, cap: int, model: ModelEntry | None, default: int | None = None) -> int:
    if not isinstance(payload, ChatPayload):
        return 0
    if model is not None and model.max_output_tokens:
        cap = min(cap, model.max_output_tokens)
    for key in ("max_tokens", "max_completion_tokens"):
        value = payload.params.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return min(value, cap)
    return min(default, cap) if default is not None else cap


def estimate_request(ctx: InspectionContext, policy: Policy, default_output: int | None = None) -> Estimate:
    payload = ctx.payload
    if not isinstance(payload, ChatPayload | EmbeddingsPayload):
        return ZERO
    model = resolve_model(policy, ctx.model_requested)
    if model is None:  # `auto` / unknown: priced as the local target
        model = resolve_model(policy, policy.routing.targets.local)
    inp = input_tokens_of(payload)
    out = requested_output(payload, policy.budgets.stream.max_output_tokens, model, default_output)
    usage = compute_usage(model, UpstreamUsage(input_tokens=inp, output_tokens=out))
    return Estimate(input_tokens=inp, output_tokens=out, usd=usage.usd, gpu_seconds=usage.gpu_seconds)
