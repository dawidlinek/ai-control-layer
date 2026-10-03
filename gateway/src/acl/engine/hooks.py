"""Request-flow hooks (orchestrator-owned seam).

Packages that must observe enforced traffic register an object in `app.state.flow_hooks` implementing any of:

    async def on_commit(self, ctx: InspectionContext, decision: Decision) -> None
        # after a decision was enforced (all points: ingress/egress/tool_call/tool_result/embeddings);
        # e.g. loop counters, expected tool_call ids for bypass detection
    async def on_usage(self, ctx: InspectionContext, decision: Decision, route: RouteInfo | None, usage: Usage) -> None
        # after an upstream call was metered; e.g. budget ledger reconciliation

Hooks run in registration order; an exception is logged and never breaks the request (the decision
was already enforced). Hooks MUST NOT be used to make enforcement decisions — that is what controls are for.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


async def run_hooks(app: Any, method: str, *args: Any) -> None:
    for hook in list(getattr(app.state, "flow_hooks", []) or []):
        fn = getattr(hook, method, None)
        if fn is None:
            continue
        try:
            await fn(*args)
        except Exception:
            log.exception("flow hook %s.%s failed", type(hook).__name__, method)
