"""Request-scoped "budget exhausted" signal from SEC-BUDGET-01 to the router.

The budget control answers `route_local` when the cloud budget is spent. The router must then serve a local
model *and mark the response degraded* with a "budget exhausted" reason (never silently). The chat flow only
hands the router a boolean `force_local`, so this module carries the reason across the one gap in the flow:

    ASGI middleware  → creates a mutable holder in a ContextVar per HTTP request
    SEC-BUDGET-01    → `signal_budget_exhausted(reason)` while inspecting (controls run in `gather` child
                       tasks; they inherit the holder reference, so their write is visible to the parent)
    Router.route()   → `budget_exhausted_reason()` after the request's ingress decision

Outside an HTTP request (dry-run, unit tests, `/v1/decide`) there is no holder and both calls are no-ops.
The cleaner fix is a field on the router request filled by the chat flow; see `RouteRequest.budget_exhausted`.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

_HOLDER: ContextVar[dict[str, str] | None] = ContextVar("acl_budget_signal", default=None)


class BudgetSignalMiddleware:
    """Pure ASGI middleware (no `BaseHTTPMiddleware`: that would run the app in a copied context)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = _HOLDER.set({})
        try:
            await self.app(scope, receive, send)
        finally:
            _HOLDER.reset(token)


def signal_budget_exhausted(reason: str) -> None:
    holder = _HOLDER.get()
    if holder is not None:
        holder["budget_exhausted"] = reason


def budget_exhausted_reason() -> str | None:
    holder = _HOLDER.get()
    return holder.get("budget_exhausted") if holder is not None else None
