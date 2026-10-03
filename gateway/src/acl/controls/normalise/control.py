"""SEC-NORM-01: stage-0 normalisation (concept §6.2).

* NFKC, zero-width / bidi / Unicode-tag stripping (hidden ASCII in tag characters is decoded into a view);
* chat-template special tokens (`<|im_start|>`, `[INST]`, ...) are stripped; a hit is a forged-turn
  attempt → finding + `forged_turn_action` (default `monitor`) and, for untrusted sources, an
  integrity-untrusted label;
* Base64 / hex / URL-encoded segments are decoded and published as views so later controls rescan them;
* tool calls are normalised into a typed `ToolIntent`; malformed calls fail closed (block, final).

Outputs (merged into `ctx.attributes` by the pipeline):
    payload        normalised payload (same object when nothing changed)
    decoded_views  list[{field, start, end, text}]  (start/end: span of the encoded token in `payload`)
    intent         ToolIntent for `tool_call` payloads
Findings from this control carry the field only (offsets would refer to an intermediate string).
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Finding, LabelUpdate, Verdict
from acl.contracts.inspection import InspectionContext, ToolCallPayload
from acl.controls.base import Control, register_control
from acl.controls.normalise.decode import count_template_tokens, find_views, normalise_text
from acl.controls.normalise.intent import MalformedCall, build_intent, validate_arguments
from acl.controls.normalise.walk import TooDeep, set_path, walk_leaves

_UNTRUSTED_POINTS = frozenset(
    {InspectionPoint.tool_result, InspectionPoint.mcp_tools_list, InspectionPoint.mcp_initialize}
)


class NormaliseParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_decode_depth: int = Field(default=2, ge=1, le=4)
    max_views: int = Field(default=32, ge=1, le=256)
    min_base64_len: int = Field(default=16, ge=8)
    min_hex_len: int = Field(default=12, ge=8)
    strip_template_tokens: bool = True
    forged_turn_action: Action = Action.monitor
    hidden_tag_min_len: int = Field(default=8, ge=1, description="Smuggled tag-character text this long is reported.")


@register_control
class NormaliseControl(Control):
    type = "normalise"
    phase = Phase.normalise
    Params = NormaliseParams
    # Never cached: the verdict publishes the request's own normalised payload in `outputs`, which the
    # request flow forwards upstream. Replaying it for another request leaked data across users (CP1).
    # Normalisation is sub-millisecond, so caching buys nothing.
    cacheable = False

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: NormaliseParams = self.params  # type: ignore[assignment]
        payload = ctx.payload
        findings: list[Finding] = []
        views: list[dict] = []
        forged = 0
        hidden = 0
        smuggled_total = 0

        try:
            leaves = walk_leaves(payload)
            malformed = self._validate(payload, leaves)
        except TooDeep:
            malformed = MalformedCall("payload_too_deep")
            leaves = []
        if malformed is not None:
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=[self.id],
                findings=[Finding(entity_type="MALFORMED_TOOL_CALL", field=malformed.field, rule_id=self.id)],
                reason=f"malformed tool call ({malformed.code}); failing closed",
            )

        data = None
        changed = 0
        normalised_texts: dict[str, str] = {}
        for leaf in leaves:
            res = normalise_text(leaf.text, json_args=leaf.json_args, strip_templates=p.strip_template_tokens)
            text = res.text
            if res.changed:
                if data is None:
                    data = payload.model_dump(mode="python")
                set_path(data, leaf.path, text)
                changed += 1
            normalised_texts[leaf.field] = text
            hidden += res.hidden_chars
            if res.forged_tokens:
                forged += res.forged_tokens
                findings.append(Finding(entity_type="FORGED_TURN_TOKEN", field=leaf.field, score=1.0, rule_id=self.id))
            for pos, decoded in res.smuggled:
                if len(decoded) >= p.hidden_tag_min_len:
                    smuggled_total += 1
                    pos = min(pos, len(text))
                    views.append({"field": leaf.field, "start": pos, "end": pos, "text": decoded})
                    findings.append(
                        Finding(entity_type="HIDDEN_UNICODE_TAGS", field=leaf.field, score=0.9, rule_id=self.id)
                    )
            for v in find_views(
                text,
                depth=p.max_decode_depth,
                max_views=p.max_views - len(views),
                min_b64=p.min_base64_len,
                min_hex=p.min_hex_len,
            ):
                views.append({"field": leaf.field, "start": v.start, "end": v.end, "text": v.text})
                if p.strip_template_tokens and count_template_tokens(v.text):
                    forged += 1
                    findings.append(
                        Finding(
                            entity_type="FORGED_TURN_TOKEN",
                            field=leaf.field,
                            start=v.start,
                            end=v.end,
                            score=0.9,
                            rule_id=self.id,
                        )
                    )
            if len(views) >= p.max_views:
                break

        normalised = type(payload).model_validate(data) if data is not None else payload
        outputs: dict = {"payload": normalised, "decoded_views": views}
        if isinstance(normalised, ToolCallPayload):
            try:
                outputs["intent"] = build_intent(normalised)
            except (ValueError, TypeError, RecursionError):  # defensive: never let a parser bug pass a call through
                return self.verdict(
                    action=Action.block,
                    final=True,
                    rule_ids=[self.id],
                    findings=[Finding(entity_type="MALFORMED_TOOL_CALL", field="arguments", rule_id=self.id)],
                    reason="tool call could not be normalised; failing closed",
                )

        flagged = bool(forged or smuggled_total)
        notes = []
        if changed:
            notes.append(f"normalised {changed} text(s)")
        if hidden:
            notes.append(f"removed {hidden} hidden character(s)")
        if forged:
            notes.append(f"found {forged} chat-template token(s)")
        if views:
            notes.append(f"decoded {len(views)} segment(s)")
        if not flagged:
            return self.verdict(reason="; ".join(notes) or None, outputs=outputs)

        labels = LabelUpdate(integrity_untrusted=True) if ctx.point in _UNTRUSTED_POINTS else None
        action = p.forged_turn_action
        return self.verdict(
            action=action,
            rule_ids=[self.id] if action not in (Action.allow, Action.monitor) else [],
            findings=findings,
            labels=labels,
            reason="; ".join(notes),
            outputs=outputs,
        )

    # ------------------------------------------------------------------ helpers

    def _validate(self, payload, leaves) -> MalformedCall | None:
        """Fail-closed structural checks for tool calls (direct, or inside chat/completion tool_calls)."""
        try:
            if payload.kind == "tool_call":
                validate_arguments(payload.tool, payload.arguments)
                return None
            calls = []
            if payload.kind == "chat":
                for i, m in enumerate(payload.messages):
                    for k, tc in enumerate(m.tool_calls or []):
                        calls.append((f"messages[{i}].tool_calls[{k}]", tc))
            elif payload.kind == "completion":
                calls = [(f"tool_calls[{k}]", tc) for k, tc in enumerate(payload.tool_calls)]
            for prefix, tc in calls:
                raw = tc.function.arguments
                if not isinstance(raw, str):
                    raise MalformedCall("arguments_not_string", f"{prefix}.function.arguments")
                parsed = {} if not raw.strip() else _loads(raw, f"{prefix}.function.arguments")
                validate_arguments(tc.function.name, parsed, f"{prefix}.function.arguments")
        except MalformedCall as exc:
            return exc
        return None


def _loads(raw: str, field: str):
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise MalformedCall("unparseable_arguments", field) from exc
