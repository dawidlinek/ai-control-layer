"""Cost of a repeated task (tokens, USD, GPU-seconds, retries) and the counterfactual saving as a skill.

Observed USD / GPU-seconds come from the audit index (priced by the gateway at request time). The counterfactual
prices one request per run (no retries) on the draft skill's model, with the model pricing from policy.
"""

from __future__ import annotations

from acl.contracts.admin import InsightCost
from acl.contracts.common import DATA_CLASS_ORDER, ConnectorTier, DataClass
from acl.insights.records import PromptRecord
from acl.insights.recurrence import Recurrence, Run
from acl.policy.models import ModelEntry, Policy
from acl.routing.connectors.base import UpstreamUsage
from acl.routing.metering import compute_usage


def model_cost(model: ModelEntry, tokens_in: int, tokens_out: int) -> tuple[float, float]:
    """(USD, GPU-seconds) of one request on `model` (no upstream timings → the model's GPU-second estimate)."""
    usage = compute_usage(model, UpstreamUsage(input_tokens=tokens_in, output_tokens=tokens_out))
    return usage.usd, usage.gpu_seconds


def per_run_tokens(records: list[PromptRecord], runs: list[Run]) -> tuple[int, int]:
    """Typical (input, output) tokens of one run's first request."""
    if not runs:
        return 0, 0
    firsts = [records[run.members[0]] for run in runs]
    return (
        round(sum(r.tokens_in for r in firsts) / len(firsts)),
        round(sum(r.tokens_out for r in records) / len(records)),
    )


def estimate_cost(
    records: list[PromptRecord],
    runs: list[Run],
    rec: Recurrence,
    *,
    window_days: int,
    skill_model: ModelEntry | None,
) -> InsightCost:
    usd = sum(r.usd for r in records)
    gpu = sum(r.gpu_seconds for r in records)
    n_runs = max(1, len(runs))
    months = max(window_days, 1) / 30.0
    cost = InsightCost(
        runs=len(runs),
        requests=len(records),
        retries=rec.retries,
        tokens_in=sum(r.tokens_in for r in records),
        tokens_out=sum(r.tokens_out for r in records),
        usd=round(usd, 6),
        gpu_seconds=round(gpu, 3),
        wall_clock_minutes=rec.minutes_total,
        usd_per_run=round(usd / n_runs, 6),
        gpu_seconds_per_run=round(gpu / n_runs, 3),
    )
    if skill_model is not None:
        tin, tout = per_run_tokens(records, runs)
        s_usd, s_gpu = model_cost(skill_model, tin, tout)
        runs_month = len(runs) / months
        cost.skill_model = skill_model.id
        cost.skill_usd_per_run = round(s_usd, 6)
        cost.skill_gpu_seconds_per_run = round(s_gpu, 3)
        cost.saving_usd_month = round(usd / months - runs_month * s_usd, 4)
        cost.saving_gpu_seconds_month = round(gpu / months - runs_month * s_gpu, 2)
    return cost


def cheapest_adequate_model(
    policy: Policy,
    usable: dict[str, list[DataClass]],
    data_class: DataClass,
    tokens_in: int,
    tokens_out: int,
    adequate_specialists: set[str],
) -> ModelEntry | None:
    """Cheapest chat model the group may use for this data class. Specialists only when they fit the task.

    Ranking: USD per run, then local before cloud, then GPU-seconds, then id (deterministic).
    """
    models = policy.model_by_id()
    best: tuple[tuple[float, int, float, str], ModelEntry] | None = None
    for mid, classes in usable.items():
        m = models.get(mid)
        if m is None or not m.enabled or "chat" not in m.capabilities or data_class not in classes:
            continue
        if m.specialist is not None and mid not in adequate_specialists:
            continue
        usd, gpu = model_cost(m, tokens_in, tokens_out)
        local = 0 if policy.connectors[m.connector].tier == ConnectorTier.local else 1
        key = (round(usd, 9), local, gpu, mid)
        if best is None or key < best[0]:
            best = (key, m)
    return best[1] if best else None


def classes_up_to(data_class: DataClass, allowed: list[DataClass]) -> list[DataClass]:
    """Data classes a skill accepts: everything up to the observed class that the model is usable for."""
    top = DATA_CLASS_ORDER[data_class]
    return [c for c in sorted(allowed, key=lambda c: DATA_CLASS_ORDER[c]) if DATA_CLASS_ORDER[c] <= top]
