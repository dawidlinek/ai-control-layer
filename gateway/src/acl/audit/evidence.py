"""Typed incident evidence: a pure view of `(category, detail)` as an `IncidentEvidence` (discriminated on `kind`).

The producers keep writing the free-form `detail` map (unchanged, so old rows and old readers keep working); this
module turns it into the typed `Incident.evidence` at read time. Nothing here sees raw sensitive values: `detail` only
carries hashes, rule ids, flag labels and counters. Anything unexpected degrades to `GenericEvidence`, never an error.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from pydantic import TypeAdapter, ValidationError

from acl.contracts.admin import GenericEvidence, IncidentEvidence

_ADAPTER: TypeAdapter[IncidentEvidence] = TypeAdapter(IncidentEvidence)
_MAX_FACT = 200
Builder = Callable[[Mapping[str, Any], datetime | None], dict[str, Any]]


def _s(v: Any) -> str | None:
    return v if isinstance(v, str) and v.strip() else None


def _n(v: Any) -> float | None:
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def _i(v: Any) -> int | None:
    return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def _strs(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _mcp_rug_pull(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    tool = _s(d.get("tool")) or ""
    server = _s(d.get("server")) or ""
    quarantined = " The tool is quarantined." if d.get("status") == "quarantined" else ""
    return {
        "kind": "mcp_rug_pull",
        "summary": f"MCP tool '{tool}' on server '{server}' changed after it was approved.{quarantined}",
        "server": server,
        "tool": tool,
        "tool_id": _s(d.get("tool_id")) or f"{server}:{tool}",
        "status": _s(d.get("status")),
        "approved_hash": _s(d.get("pinned_hash")),
        "approved_at": _s(d.get("pinned_at")),
        "new_hash": _s(d.get("current_hash")),
        "changed_at": _s(d.get("changed_at")) or created_at,
        "description_diff": _s(d.get("description_diff")),
        "findings": _strs(d.get("reasons")),
    }


def _mcp_flagged(category: str) -> Builder:
    def build(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
        tool = _s(d.get("tool_id")) or _s(d.get("tool")) or ""
        what = (
            "was quarantined because its definition looks poisoned"
            if category == "mcp_tool_poisoning"
            else "has the same name as an existing tool"
        )
        return {
            "kind": category,
            "summary": f"MCP tool '{tool}' {what}.",
            "server": _s(d.get("server")) or "",
            "tool": _s(d.get("tool")) or "",
            "tool_id": _s(d.get("tool_id")) or tool,
            "status": _s(d.get("status")),
            "new_hash": _s(d.get("current_hash")),
            "findings": _strs(d.get("reasons")),
        }

    return build


def _mcp_protocol(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    codes = _strs(d.get("violations"))
    server = _s(d.get("server")) or "?"
    return {
        "kind": "mcp_protocol_violation",
        "summary": f"MCP server '{server}' broke the protocol rules: {', '.join(codes) or 'see detail'}.",
        "server": _s(d.get("server")),
        "violations": codes,
    }


def _canary(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    return {
        "kind": "canary_triggered",
        "summary": f"Canary data returned by '{_s(d.get('tool')) or 'an MCP tool'}' was redacted.",
        "tool": _s(d.get("tool")),
        "server": _s(d.get("server")),
        "occurrences": _i(d.get("canary_occurrences")),
    }


def _budget(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    level = _s(d.get("level"))
    node = _s(d.get("node"))
    scope = _s(d.get("scope"))
    breaker = _s(d.get("breaker"))
    rule = _s(d.get("rule_id")) or next(iter(_strs(d.get("rule_ids"))), None)
    owner = node or scope or "a budget"
    if level == "loop":
        summary = f"A runaway signal ({rule or 'loop detector'}) fired for {owner}."
    elif breaker == "open":
        summary = f"The circuit breaker opened on {owner}: further calls are blocked until it cools down."
    else:
        summary = f"{owner} {'reached its limit' if level == 'hard' else 'is approaching its limit'}."
    session = next((x.split(":", 1)[1] for x in (node, scope) if x and x.startswith("session:")), None)
    return {
        "kind": "budget_breach",
        "summary": summary,
        "level": level if level in ("soft", "hard", "loop") else None,
        "node": node,
        "scope": scope,
        "session_id": session,
        "meter": _s(d.get("meter")),
        "limit": _n(d.get("limit")),
        "used": _n(d.get("used")),
        "projected": _n(d.get("projected")),
        "action": _s(d.get("action")),
        "breaker": breaker if breaker in ("closed", "open", "half_open") else None,
        "cooldown_s": _i(d.get("cooldown_s")),
        "loop_rule": rule if level == "loop" else None,
    }


def _forbidden_model(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    model = _s(d.get("model"))
    which = f"the model '{model}'" if model else "a model"
    return {
        "kind": "forbidden_model",
        "summary": f"A request asked for {which}, which is not allowed for this user.",
        "model": model,
    }


def _blocked(category: str) -> Builder:
    def build(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
        by = _s(d.get("decided_by"))
        what = "response" if category == "blocked_response" else "request"
        return {
            "kind": category,
            "summary": f"A {what} was blocked" + (f" by {by}." if by else "."),
            "point": _s(d.get("point")),
            "decided_by": by,
        }

    return build


def _plugin_bypass(d: Mapping[str, Any], created_at: datetime | None) -> dict[str, Any]:
    return {
        "kind": "plugin_bypass",
        "summary": f"A client-local tool ran without asking the gateway first: {_s(d.get('tool')) or 'unknown tool'}.",
        "tool": _s(d.get("tool")),
        "tool_call_id_hash": _s(d.get("tool_call_id_hash")),
        "explanation": _s(d.get("explanation")),
    }


_BUILDERS: dict[str, Builder] = {
    "mcp_rug_pull": _mcp_rug_pull,
    "mcp_tool_poisoning": _mcp_flagged("mcp_tool_poisoning"),
    "mcp_name_collision": _mcp_flagged("mcp_name_collision"),
    "mcp_protocol_violation": _mcp_protocol,
    "canary_triggered": _canary,
    "budget_breach": _budget,
    "forbidden_model": _forbidden_model,
    "blocked_request": _blocked("blocked_request"),
    "blocked_response": _blocked("blocked_response"),
    "plugin_bypass": _plugin_bypass,
}


def _generic(category: str, d: Mapping[str, Any]) -> GenericEvidence:
    facts: dict[str, str | int | float | bool] = {}
    for key, value in d.items():
        if isinstance(value, bool | int | float):
            facts[str(key)] = value
        elif isinstance(value, str) and value:
            facts[str(key)] = value[:_MAX_FACT]
    return GenericEvidence(category=category, summary=_s(d.get("title")), facts=facts)


def evidence_for(
    category: str, detail: Mapping[str, Any] | None, created_at: datetime | None = None
) -> IncidentEvidence:
    """Typed evidence for an incident; `GenericEvidence` for unknown categories or unexpected detail shapes."""
    d = detail or {}
    build = _BUILDERS.get(category)
    if build is not None:
        try:
            return _ADAPTER.validate_python(build(d, created_at))
        except (ValidationError, TypeError, ValueError):
            pass
    return _generic(category, d)
