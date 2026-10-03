"""SEC-FLOW-01 `rule_of_two`: the lethal-trifecta gate at the `tool_call` point (concept §9, §16 row 6).

    untrusted  = session integrity untrusted, or taint `untrusted`
    sensitive  = taint `sensitive`, or confidentiality >= confidential
    sink       = the tool is labelled `external_egress` (or is unknown to the catalogue, or is a shell tool whose
                 command sends data out / publishes: `curl`, `git push`, `scp`, `npm publish`, ..., or runs
                 workspace / inline code: `pytest`, `make`, `npm test`, `python x.py`, `node -e`, `./run.sh`)

    untrusted AND sensitive AND sink   → preset `rule_of_two_action` (balanced: require_approval, strict: block)
    `taint_mode: full` (paranoid)      → untrusted AND sink → block, even without sensitive data

The verdict is a pure function of (session labels, tool catalogue, call, preset). It does not look at classifier scores,
judges, or any other control, so it holds with every semantic control disabled, and no AI-tier verdict can relax it
(`compose_decision`: AI tiers only raise severity; a `block` here is `final`). It is intentionally not `locked`: a
`monitor` preset must stay log-only.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from acl.contracts.common import DATA_CLASS_ORDER, Action, DataClass, Integrity, Phase, TaintFlag
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext, SessionLabels, ToolCallPayload
from acl.controls.base import Control, register_control
from acl.controls.taint.sinks import call_is_sink


class RuleOfTwoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


def session_flags(ctx: InspectionContext) -> tuple[bool, bool]:
    """(untrusted, sensitive) from the session labels joined with everything detected earlier in this request
    (`labels_so_far`, published by the pipeline after each phase) — a PESEL inside the sink call itself counts."""
    running = ctx.attributes.get("labels_so_far")
    labels = running if isinstance(running, SessionLabels) else ctx.session.labels
    untrusted = labels.integrity == Integrity.untrusted or TaintFlag.untrusted in labels.taint
    sensitive = (
        TaintFlag.sensitive in labels.taint
        or DATA_CLASS_ORDER[labels.confidentiality] >= DATA_CLASS_ORDER[DataClass.confidential]
    )
    return untrusted, sensitive


@register_control
class RuleOfTwoControl(Control):
    type = "rule_of_two"
    # Runs in the `decide` phase, after every detector, so it judges the session labels raised by this very call.
    phase = Phase.decide
    Params = RuleOfTwoParams
    cacheable = False  # depends on session state

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        payload = ctx.attributes.get("payload")
        if not isinstance(payload, ToolCallPayload):
            payload = ctx.payload
        if not isinstance(payload, ToolCallPayload):
            return self.verdict(reason="not a tool call")
        untrusted, sensitive = session_flags(ctx)
        if not untrusted:
            return self.verdict(reason="session has no untrusted input")
        policy = self.deps.get("policy")
        tool = policy.tools.get(payload.tool) if policy is not None else None  # type: ignore[call-overload]
        sink, sink_reason = call_is_sink(tool, payload, untrusted=True)  # only reached for an untrusted session
        if not sink:
            return self.verdict(reason="call is not an external-egress sink")

        settings = self.preset_settings(ctx)
        full = settings is not None and settings.taint_mode == "full"
        if sensitive and full:
            action, rule, why = Action.block, "TRIFECTA", "untrusted input + sensitive data + external egress"
        elif sensitive:
            action = settings.rule_of_two_action if settings is not None else Action.block
            rule, why = "TRIFECTA", "untrusted input + sensitive data + external egress"
        elif full:
            action, rule, why = Action.block, "TAINT_FULL", "untrusted input can never reach a sink (taint_mode: full)"
        else:
            return self.verdict(reason="untrusted input but no sensitive data in the session")
        if action in (Action.allow,):
            return self.verdict(reason=f"{why}: preset allows")
        return self.verdict(
            action=action,
            final=action == Action.block,
            rule_ids=[self.id, f"{self.id}.{rule}"],
            reason=f"{why} ({sink_reason}); sources: {', '.join(ctx.session.labels.sources[-5:]) or 'session labels'}",
            labels=None,
        )
