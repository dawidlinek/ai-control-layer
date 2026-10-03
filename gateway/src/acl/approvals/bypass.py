"""Plugin-bypass detection (concept §9 "Built-in tools that bypass MCP", §5.1; flow-hook observer, never enforces).

OpenCode runs its built-in tools on the developer's machine; the managed plugin asks `/v1/decide` before each one. If
the plugin is missing, patched or fails open, the model still *emits* the tool call and the client still *returns its
result* in the next request. This hook correlates the three observable facts per session:

    egress   the model emitted tool_call `id` for a client-local tool (`opencode.*`)   → remember (bounded, TTL)
    decide   `/v1/decide` was asked about `tool_call_id`                                → mark decided
    ingress  a `role: tool` message carries that id                                     → emitted but never decided
                                                                                          = bypass → `incident` event

The incident has category `plugin_bypass`, rule `SEC-TOOL-01.BYPASS`, and never contains arguments or results (the
tool-call id appears only as a salted hash). One report per tool call, the history is replayed on every request.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from acl.contracts.audit import EventType
from acl.contracts.canonical import value_hash
from acl.contracts.common import InspectionPoint, Severity
from acl.contracts.decision import Decision
from acl.contracts.inspection import ChatPayload, CompletionPayload, InspectionContext, ToolCallPayload
from acl.controls.tools.catalogue import ToolNames

log = logging.getLogger(__name__)

RULE_BYPASS = "SEC-TOOL-01.BYPASS"


@dataclass
class _Call:
    tool: str | None
    ts: float
    emitted: bool = False
    decided: bool = False
    reported: bool = False


class BypassDetector:
    def __init__(
        self,
        app: Any,
        *,
        ttl_s: float = 3600.0,
        max_sessions: int = 5000,
        max_calls: int = 500,
        clock: Callable[[], float] = time.monotonic,
        salt: Callable[[], str] = lambda: "dev-salt",
    ) -> None:
        self.app = app
        self.ttl_s = ttl_s
        self.max_sessions = max_sessions
        self.max_calls = max_calls
        self._clock = clock
        self._salt = salt
        self._sessions: OrderedDict[str, OrderedDict[str, _Call]] = OrderedDict()
        self._names: tuple[int, ToolNames] | None = None
        self.reported: list[str] = []  # tool-call id hashes (introspection for tests / panel)

    # ------------------------------------------------------------ bookkeeping

    def _calls(self, session_id: str, create: bool = False) -> OrderedDict[str, _Call] | None:
        now = self._clock()
        calls = self._sessions.get(session_id)
        if calls is None:
            if not create:
                return None
            calls = self._sessions[session_id] = OrderedDict()
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(session_id)
        while calls and next(iter(calls.values())).ts + self.ttl_s < now:
            calls.popitem(last=False)
        return calls

    def _put(self, session_id: str, call_id: str, tool: str | None) -> _Call:
        calls = self._calls(session_id, create=True)
        assert calls is not None
        rec = calls.get(call_id)
        if rec is None:
            rec = calls[call_id] = _Call(tool=tool, ts=self._clock())
            while len(calls) > self.max_calls:
                calls.popitem(last=False)
        elif tool and not rec.tool:
            rec.tool = tool
        return rec

    def _resolve(self, name: str) -> str | None:
        engine = getattr(self.app.state, "engine", None)
        if engine is None:
            return None
        key = id(engine.policy)
        if self._names is None or self._names[0] != key:
            self._names = (key, ToolNames(engine.policy))
        return self._names[1].resolve(name)

    # ------------------------------------------------------------ hook

    async def on_commit(self, ctx: InspectionContext, decision: Decision) -> None:
        payload = ctx.payload
        if ctx.point == InspectionPoint.egress and isinstance(payload, CompletionPayload):
            for tc in payload.tool_calls:
                tool = self._resolve(tc.function.name)
                if tool is not None and tool.startswith("opencode.") and tc.id:
                    self._put(ctx.session_id, tc.id, tool).emitted = True
        elif ctx.point == InspectionPoint.tool_call and isinstance(payload, ToolCallPayload):
            if payload.tool_call_id:
                self._put(ctx.session_id, payload.tool_call_id, payload.tool).decided = True
        elif ctx.point == InspectionPoint.ingress and isinstance(payload, ChatPayload):
            calls = self._calls(ctx.session_id)
            if not calls:
                return
            for m in payload.messages:
                if m.role != "tool" or not m.tool_call_id:
                    continue
                rec = calls.get(m.tool_call_id)
                if rec is not None and rec.emitted and not rec.decided and not rec.reported:
                    rec.reported = True
                    await self._report(ctx, m.tool_call_id, rec)

    async def _report(self, ctx: InspectionContext, call_id: str, rec: _Call) -> None:
        call_hash = value_hash(call_id, self._salt())
        self.reported.append(call_hash)
        sink = getattr(self.app.state, "audit", None)
        if sink is None:
            log.warning("plugin bypass detected (no audit sink): tool=%s", rec.tool)
            return
        await sink.record_event(
            EventType.incident,
            severity=Severity.high,
            detail={
                "category": "plugin_bypass",
                "title": f"Client-local tool ran without /v1/decide: {rec.tool}",
                "rule_id": RULE_BYPASS,
                "tool": rec.tool,
                "tool_call_id_hash": call_hash,
                "explanation": "the model emitted the tool call and the client returned its result, "
                "but the managed plugin never asked /v1/decide",
            },
            principal=ctx.principal,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
        )
