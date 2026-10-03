"""JSON-RPC 2.0 helpers for the MCP proxy."""

from __future__ import annotations

from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# implementation-defined server errors (-32000..-32099)
BLOCKED = -32001  # refused by policy (data: rule_ids, decision_id, trace_id)
APPROVAL_REQUIRED = -32002  # data: approval_id, status, expires_at
RESULT_WITHHELD = -32003  # the tool ran, its result was withheld / could not be made safe
UPSTREAM_ERROR = -32004
UNAVAILABLE = -32005  # gateway cannot decide (no policy / audit): fail closed

SUPPORTED_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28")
LATEST_STATEFUL = "2025-11-25"


def result(request_id: Any, value: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message[:500]}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def is_request(msg: dict[str, Any]) -> bool:
    return isinstance(msg.get("method"), str) and "id" in msg and msg["id"] is not None


def is_notification(msg: dict[str, Any]) -> bool:
    return isinstance(msg.get("method"), str) and ("id" not in msg or msg["id"] is None)


def is_response(msg: dict[str, Any]) -> bool:
    return "method" not in msg and "id" in msg and ("result" in msg or "error" in msg)
