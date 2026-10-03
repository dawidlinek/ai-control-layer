"""Compose verdicts into a Decision (concept §6.3–6.5). SECURITY-CRITICAL: orchestrator reviews changes.

Invariants (tested in gateway/tests/test_engine_decide.py):
  1. A final verdict with action=block always yields action=block, regardless of anything else.
  2. AI-tier verdicts (similarity/l1/l2) can only make the outcome stricter, never relax a
     deterministic verdict.
  3. Shadow controls (mode: monitor), monitor-mode policy and `never_block` presets (`monitor`)
     never change the enforced action;
     the would-be action is recorded in `would_action`.
  4. No verdicts → allow.

Phase 0: primary action = most severe verdict action. Graded risk scoring (§6.5) is added in
Phase 2B/3A as a separate factor-composition step feeding the same invariants.
"""

from __future__ import annotations

import uuid

from acl.contracts.common import ACTION_SEVERITY, Action, PolicyMode, Taxonomy
from acl.contracts.decision import Decision, Verdict
from acl.contracts.inspection import InspectionContext
from acl.policy.models import GlobalSettings

_TRANSFORMS = {Action.redact, Action.pseudonymise, Action.sanitize, Action.route_local, Action.downgrade}


def _merge_taxonomy(verdicts: list[Verdict]) -> Taxonomy:
    merged = Taxonomy()
    for v in verdicts:
        if v.action in (Action.allow, Action.monitor):
            continue
        for field in Taxonomy.model_fields:
            bucket: list[str] = getattr(merged, field)
            for tag in getattr(v.taxonomy, field):
                if tag not in bucket:
                    bucket.append(tag)
    return merged


def compose_decision(
    ctx: InspectionContext,
    verdicts: list[Verdict],
    settings: GlobalSettings,
    *,
    latency_ms: float = 0.0,
    shadow_controls: frozenset[str] = frozenset(),
    never_block: bool = False,
) -> Decision:
    enforced = [v for v in verdicts if v.control_id not in shadow_controls]

    primary: Verdict | None = None
    for v in enforced:
        if (
            primary is None
            or ACTION_SEVERITY[v.action] > ACTION_SEVERITY[primary.action]
            or (ACTION_SEVERITY[v.action] == ACTION_SEVERITY[primary.action] and v.final and not primary.final)
        ):
            primary = v
    final_block = next((v for v in enforced if v.final and v.action == Action.block), None)
    if final_block is not None:
        primary = final_block

    action = primary.action if primary is not None else Action.allow
    applied: list[Action] = []
    for v in enforced:
        if v.action in _TRANSFORMS and v.action not in applied:
            applied.append(v.action)
    if action not in (Action.allow, Action.monitor) and action not in applied:
        applied.append(action)

    rule_ids: list[str] = []
    for v in enforced:
        if v.action not in (Action.allow, Action.monitor):
            for r in v.rule_ids:
                if r not in rule_ids:
                    rule_ids.append(r)

    would_action: Action | None = None
    monitor_mode = settings.mode == PolicyMode.monitor or ctx.mode == PolicyMode.monitor or never_block
    if monitor_mode and action not in (Action.allow, Action.monitor):
        would_action = action
        action = Action.monitor
        applied = []

    return Decision(
        decision_id=str(uuid.uuid4()),
        trace_id=ctx.trace_id,
        point=ctx.point,
        action=action,
        applied=applied,
        would_action=would_action,
        final=final_block is not None and not monitor_mode,
        decided_by=primary.control_id if primary is not None and primary.action != Action.allow else None,
        decided_phase=primary.phase if primary is not None and primary.action != Action.allow else None,
        rule_ids=rule_ids,
        risk_score=max((v.score or 0.0 for v in enforced if v.action != Action.allow), default=0.0),
        reason=(primary.reason or "") if primary is not None and primary.action != Action.allow else "",
        verdicts=verdicts,
        labels_after=ctx.session.labels.model_copy(deep=True),
        taxonomy=_merge_taxonomy(enforced),
        versions=ctx.versions,
        latency_ms=latency_ms,
    )
