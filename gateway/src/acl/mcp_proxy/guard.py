"""Enforcement helpers of the MCP proxy: evaluate a point with proxy-side overrides, and sanitise tool results.

`run_point` is `acl.engine.actions.evaluate_point` plus one thing the proxy needs: deterministic proxy checks
(quarantine, grants, canaries) must show up in the audit record as the block they are, even if the matching
control is disabled. So the point is evaluated without recording, `force_block` may escalate the decision, and
only then the record is written and the decision committed.

Tool results (`Segments`): every model-readable string of a `CallToolResult` (text blocks, embedded resource
text, resource-link names, every string leaf of `structuredContent`) becomes one segment; the segments are
joined with a separator, inspected as one `ToolResultPayload`, and written back after the engine's
redact/pseudonymise/sanitize replacements. Only whitelisted fields of the result are forwarded (`_meta`,
annotations, unknown block types are dropped), so nothing escapes inspection.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Decision
from acl.contracts.inspection import ClientInfo, InspectionContext, Payload
from acl.engine.actions import GatewayUnavailable, commit_decision, evaluate_point

SEP = "\n␞\n"  # SYMBOL FOR RECORD SEPARATOR: joins segments; a segment containing it is refused
CANARY_MASK = "[REDACTED:CANARY]"
MAX_BLOB_SCAN = 65_536


class ResultRefused(Exception):
    """The result cannot be inspected faithfully (framing character, size): withhold it (fail closed)."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


# ---------------------------------------------------------------------------------------------- decisions


def escalate_to_block(decision: Decision, rule_id: str, reason: str, decided_by: str) -> None:
    decision.action = Action.block
    decision.final = True
    if Action.block not in decision.applied:
        decision.applied.append(Action.block)
    if rule_id not in decision.rule_ids:
        decision.rule_ids.append(rule_id)
    decision.decided_by = decided_by
    decision.decided_phase = Phase.decide
    decision.reason = reason
    decision.risk_score = max(decision.risk_score, 0.9)


@dataclass(frozen=True)
class ForceBlock:
    rule_id: str
    reason: str
    decided_by: str = "MCP-PROXY"


async def record_point(app: Any, ctx: InspectionContext, decision: Decision) -> None:
    from acl.audit.builder import redacted_text
    from acl.engine.transforms import unaddressable_fields

    audit = getattr(app.state, "audit", None)
    engine = app.state.engine
    if audit is None or engine is None:
        raise GatewayUnavailable("audit log unavailable")
    redacted = None
    if engine.policy.global_.store_redacted_payloads:
        fields = {f.field for v in decision.verdicts for f in v.findings if f.field}
        if not (fields and fields & unaddressable_fields(ctx.payload)):
            redacted = redacted_text(ctx, decision.verdicts)
    await audit.record_decision(ctx, decision, redacted_payload=redacted)


async def run_point(
    app: Any,
    principal: Any,
    *,
    point: InspectionPoint,
    payload: Payload,
    client_session: str | None,
    attributes: dict[str, Any] | None = None,
    client: ClientInfo | None = None,
    force_block: ForceBlock | None = None,
    record_when: Callable[[Decision], bool] | None = None,
    commit: bool = True,
) -> tuple[InspectionContext, Decision]:
    ctx, decision = await evaluate_point(
        app,
        principal,
        point=point,
        payload=payload,
        client_session=client_session,
        client=client,
        attributes=attributes,
        commit=False,
        record=False,
    )
    if force_block is not None and decision.action != Action.block:
        escalate_to_block(decision, force_block.rule_id, force_block.reason, force_block.decided_by)
    if record_when is None or record_when(decision):
        await record_point(app, ctx, decision)
    if commit:
        await commit_decision(app, ctx, decision)
    return ctx, decision


# ---------------------------------------------------------------------------------------------- results


@dataclass
class Segments:
    """Model-readable strings of a result plus the ability to write replacements back."""

    out: dict[str, Any]
    texts: list[str] = field(default_factory=list)
    _setters: list[Callable[[str], None]] = field(default_factory=list)

    def add(self, container: Any, key: Any) -> None:
        value = container[key]
        self.texts.append(value)
        self._setters.append(lambda new, c=container, k=key: c.__setitem__(k, new))

    def joined(self) -> str:
        if any(SEP in t for t in self.texts):
            raise ResultRefused("MCP_RESULT_FRAMING", "result contains the gateway's framing character")
        return SEP.join(self.texts)

    def write_back(self, content: str) -> dict[str, Any]:
        parts = content.split(SEP) if self.texts else []
        if len(parts) != len(self._setters):
            raise ResultRefused("MCP_RESULT_FRAMING", "result could not be mapped back after inspection")
        for setter, part in zip(self._setters, parts, strict=True):
            setter(part)
        return self.out

    def redact_canaries(self, canaries: list[str]) -> int:
        """Mask canary values in place (before inspection); returns how many were masked."""
        hits = 0
        for i, text in enumerate(self.texts):
            new = text
            for canary in canaries:
                if canary and canary in new:
                    hits += new.count(canary)
                    new = new.replace(canary, CANARY_MASK)
            if new != text:
                self.texts[i] = new
                self._setters[i](new)
        return hits


def _walk_strings(node: Any, seg: Segments, depth: int = 0) -> None:
    if depth > 32:
        raise ResultRefused("MCP_RESULT_DEPTH", "structured result is nested too deeply")
    if isinstance(node, dict):
        for k in list(node):
            if isinstance(node[k], str):
                seg.add(node, k)
            else:
                _walk_strings(node[k], seg, depth + 1)
    elif isinstance(node, list):
        for i in range(len(node)):
            if isinstance(node[i], str):
                seg.add(node, i)
            else:
                _walk_strings(node[i], seg, depth + 1)


def build_segments(result: dict[str, Any], *, max_bytes: int) -> Segments:
    """Whitelisted copy of a `CallToolResult` with its strings registered as segments."""
    out: dict[str, Any] = {"content": [], "isError": bool(result.get("isError"))}
    seg = Segments(out)
    for block in result.get("content") or []:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text" and isinstance(block.get("text"), str):
            nb = {"type": "text", "text": block["text"]}
            out["content"].append(nb)
            seg.add(nb, "text")
        elif (
            btype in ("image", "audio")
            and isinstance(block.get("data"), str)
            and isinstance(block.get("mimeType"), str)
        ):
            out["content"].append({"type": btype, "data": block["data"], "mimeType": block["mimeType"]})
        elif btype == "resource" and isinstance(block.get("resource"), dict):
            res = block["resource"]
            nres: dict[str, Any] = {k: res[k] for k in ("uri", "mimeType") if isinstance(res.get(k), str)}
            if isinstance(res.get("text"), str):
                nres["text"] = res["text"]
            elif isinstance(res.get("blob"), str):
                if len(res["blob"]) > MAX_BLOB_SCAN:
                    out["content"].append({"type": "text", "text": "[binary resource omitted by the gateway]"})
                    continue
                nres["blob"] = res["blob"]
            nb = {"type": "resource", "resource": nres}
            out["content"].append(nb)
            for key in ("uri", "text", "blob"):
                if key in nres:
                    seg.add(nres, key)
        elif btype == "resource_link" and isinstance(block.get("uri"), str):
            nb = {
                "type": "resource_link",
                **{k: block[k] for k in ("uri", "name", "title", "description") if isinstance(block.get(k), str)},
            }
            if "mimeType" in block and isinstance(block["mimeType"], str):
                nb["mimeType"] = block["mimeType"]
            out["content"].append(nb)
            for key in ("uri", "name", "title", "description"):
                if key in nb:
                    seg.add(nb, key)
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        out["structuredContent"] = copy.deepcopy(structured)
        _walk_strings(out["structuredContent"], seg)
    total = sum(len(t) for t in seg.texts)
    if total > max_bytes:
        raise ResultRefused("MCP_RESULT_SIZE", "result exceeds the configured size limit")
    return seg


def build_generic_segments(result: dict[str, Any], *, max_bytes: int) -> Segments:
    """Segments for any JSON result (resources/list, resources/read, prompts/get ...): every string leaf."""
    data = copy.deepcopy(result)
    data.pop("_meta", None)
    seg = Segments(data)
    _walk_strings(data, seg)
    if sum(len(t) for t in seg.texts) > max_bytes:
        raise ResultRefused("MCP_RESULT_SIZE", "result exceeds the configured size limit")
    return seg
