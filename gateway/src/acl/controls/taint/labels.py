"""SEC-TAINT-01 `taint_labels`: raise session IFC labels from tool traffic (concept §9 "Labels for IFC").

Points and rules (labels only ever rise: `compose_decision` joins them into `labels_after`, the session store merges):

  tool_result   the result of a tool labelled `reads_untrusted`, or of a tool that is not in the catalogue
                → integrity untrusted;  `touches_sensitive` → confidentiality confidential + taint `sensitive`
  ingress       chat messages with `role: tool` (OpenCode / LibreChat send tool results back as history): the tool
                name comes from the assistant `tool_calls` entry with the same `tool_call_id` (client built-ins map to
                `opencode.<name>`, MCP tools to `<server>.<tool>`), then the same rules apply. An unmappable tool
                message is treated as an unknown tool (untrusted). Repo content / README is untrusted per §9.
  tool_call     (param `raise_on_call`, default on) an *allowed* call to a labelled tool raises the labels at once, so
                parallel tool calls in one model step cannot race the result-time labelling; blocked / held calls raise
                nothing (the content never reaches the model).

`commit()` adds taint `egress_used` after an allowed external-egress call, and applies the `downgrade` confinement
(`allowed_tools` narrowing) like SEC-TOOL-01.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, InspectionPoint, Phase, TaintFlag
from acl.contracts.decision import Decision, LabelUpdate, Verdict
from acl.contracts.inspection import (
    ChatPayload,
    InspectionContext,
    SessionState,
    ToolCallPayload,
    ToolResultPayload,
)
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.taint.sinks import call_is_sink, labels_for_tool, merge_updates
from acl.controls.tools.catalogue import ToolNames, apply_downgrade
from acl.policy.models import ControlConfig, Policy, ToolDef


class TaintLabelsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raise_on_call: bool = Field(default=True, description="Raise labels when a labelled tool call is allowed.")
    unknown_tool_untrusted: bool = Field(default=True, description="Results of uncatalogued tools are untrusted.")


@register_control
class TaintLabelsControl(Control):
    type = "taint_labels"
    phase = Phase.deterministic
    Params = TaintLabelsParams
    cacheable = False

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        policy: Policy | None = deps.get("policy")
        self._policy = policy
        self._names = ToolNames(policy) if policy is not None else None

    # ------------------------------------------------------------ helpers

    def _tool(self, name: str | None) -> tuple[ToolDef | None, str | None]:
        if self._policy is None:
            return None, None
        tid = name if name in self._policy.tools else (self._names.resolve(name) if self._names else None)  # type: ignore[operator]
        return (self._policy.tools.get(tid) if tid else None), tid  # type: ignore[call-overload]

    def _update_for(self, name: str | None) -> tuple[LabelUpdate | None, str]:
        p: TaintLabelsParams = self.params  # type: ignore[assignment]
        tool, tid = self._tool(name)
        return labels_for_tool(tool, unknown_untrusted=p.unknown_tool_untrusted), tid or "<uncatalogued>"

    # ------------------------------------------------------------ inspect

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: TaintLabelsParams = self.params  # type: ignore[assignment]
        payload = ctx.payload
        updates: list[LabelUpdate | None] = []
        tools: list[str] = []
        if ctx.point == InspectionPoint.tool_result and isinstance(payload, ToolResultPayload):
            upd, tid = self._update_for(payload.tool)
            updates.append(upd)
            tools.append(tid)
        elif ctx.point == InspectionPoint.ingress and isinstance(payload, ChatPayload):
            calls: dict[str, str] = {}
            for m in payload.messages:
                if m.role == "assistant":
                    for tc in m.tool_calls or []:
                        calls[tc.id] = tc.function.name
                elif m.role == "tool":
                    name = calls.get(m.tool_call_id or "") or None
                    upd, tid = self._update_for(name)
                    updates.append(upd)
                    tools.append(tid)
        elif ctx.point == InspectionPoint.tool_call and p.raise_on_call and isinstance(payload, ToolCallPayload):
            tool, tid = self._tool(payload.tool)
            if tool is not None:  # unknown tools are blocked by SEC-TOOL-01; nothing reaches the model
                updates.append(labels_for_tool(tool))
                tools.append(tid or payload.tool)
        merged = merge_updates(updates)
        if merged is None:
            return self.verdict()
        names = ", ".join(dict.fromkeys(tools))[:200]
        parts = []
        if merged.integrity_untrusted:
            parts.append("untrusted")
        if merged.taint:
            parts.append("sensitive")
        return self.verdict(
            rule_ids=[self.id],
            labels=merged,
            reason=f"session labels raised ({'+'.join(parts)}) by tool output: {names}",
        )

    # ------------------------------------------------------------ commit

    async def commit(self, ctx: InspectionContext, decision: Decision) -> None:
        await apply_downgrade(self.deps, ctx, decision)
        if ctx.point != InspectionPoint.tool_call or decision.action in (Action.block, Action.require_approval):
            return
        payload = ctx.attributes.get("payload")
        if not isinstance(payload, ToolCallPayload):
            payload = ctx.payload
        if not isinstance(payload, ToolCallPayload):
            return
        tool, _ = self._tool(payload.tool)
        if tool is None or not call_is_sink(tool, payload)[0]:
            return
        await mark_egress_used(self.deps.get("sessions"), ctx.session_id, self.id)


async def mark_egress_used(sessions: object, session_id: str, source: str = "SEC-TAINT-01") -> None:
    """Add taint `egress_used` (monotonic) after an external-egress call ran."""
    if sessions is None:
        return

    def add(state: SessionState) -> SessionState:
        labels = state.labels
        if TaintFlag.egress_used in labels.taint:
            return state
        new = labels.model_copy(
            update={
                "taint": [*labels.taint, TaintFlag.egress_used],
                "sources": [*labels.sources, source][-50:] if source not in labels.sources else labels.sources,
            }
        )
        return state.model_copy(update={"labels": new})

    await sessions.update(session_id, add)  # type: ignore[attr-defined]
