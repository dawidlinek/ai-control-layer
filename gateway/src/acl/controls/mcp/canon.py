"""Canonical MCP tool form and manifest pins (concept §9, "MCP integrity").

Two hashes (lower-case hex sha256):

* **content hash** `tool_hash` — the policy's `tools.<id>.schema_pin`, and the stored pin before CP2 ("v1"):

      sha256( name \\0 description \\0 canonical_json(inputSchema) )

* **manifest pin v2** `manifest_hash` — what the proxy stores as `pinned_hash` / `current_hash` and SEC-MCP-01
  compares for drift. It covers everything of a tool that leaves the gateway: the content-hash inputs plus the
  boolean behaviour hints of `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
  Other annotation fields (`title`, ...) are never forwarded to clients and are not pinned.

      sha256( "acl-mcp-pin/v2" \\0 name \\0 description \\0 canonical_json(inputSchema) \\0 canonical_json(hints) )

  The version prefix domain-separates v2 from v1, so the stored digest itself says which algorithm produced it (no
  schema change / migration): a stored pin equal to `tool_hash(...)` of the announced tool is a legacy v1 pin and
  is upgraded in place to the v2 pin on the next listing without raising drift (`McpStore.upgrade_legacy_pins`; the
  hints announced at that moment become pinned, since v1 never covered them). Any later change of a hint is drift.

`canonical_json` sorts keys and uses compact separators (`acl.contracts.canonical.canonical_json` rules, UTF-8,
no ASCII escaping). NUL separators keep the parts unambiguous. A missing description counts as the empty string, a
missing schema / missing hints as `{}`. Admins can reproduce a policy `schema_pin` with
`python -c "from acl.controls.mcp.canon import tool_hash; print(tool_hash(name, desc, schema))"`.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tool_hash(name: str, description: str | None, input_schema: dict[str, Any] | None) -> str:
    h = hashlib.sha256()
    h.update("\0".join((name or "", description or "", canonical_json(input_schema or {}))).encode("utf-8"))
    return h.hexdigest()


def tool_hash_of(tool: dict[str, Any]) -> str:
    """Content hash of a raw MCP `Tool` object (`name`, `description`, `inputSchema`): the legacy (v1) pin."""
    schema = tool.get("inputSchema")
    return tool_hash(
        str(tool.get("name") or ""),
        tool.get("description") if isinstance(tool.get("description"), str) else "",
        schema if isinstance(schema, dict) else {},
    )


PIN_VERSION = "acl-mcp-pin/v2"
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def tool_hints(annotations: Any) -> dict[str, bool]:
    """The behaviour hints the gateway forwards to clients (booleans only); everything else is dropped."""
    if not isinstance(annotations, dict):
        return {}
    return {k: v for k, v in annotations.items() if k in HINTS and isinstance(v, bool)}


def manifest_hash(
    name: str, description: str | None, input_schema: dict[str, Any] | None, annotations: Any = None
) -> str:
    """The v2 manifest pin: content hash inputs + forwarded annotation hints, domain-separated from v1."""
    h = hashlib.sha256()
    parts = (
        PIN_VERSION,
        name or "",
        description or "",
        canonical_json(input_schema or {}),
        canonical_json(tool_hints(annotations)),
    )
    h.update("\0".join(parts).encode("utf-8"))
    return h.hexdigest()


def manifest_hash_of(tool: dict[str, Any]) -> str:
    """v2 manifest pin of a raw MCP `Tool` object."""
    schema = tool.get("inputSchema")
    return manifest_hash(
        str(tool.get("name") or ""),
        tool.get("description") if isinstance(tool.get("description"), str) else "",
        schema if isinstance(schema, dict) else {},
        tool.get("annotations"),
    )


def normalise_name(name: str) -> str:
    """Comparison form for collision / shadowing checks: case-folded, `-`/`.`/space folded to `_`."""
    return "".join("_" if c in "-. " else c for c in name.casefold())


def description_diff(old_description: str | None, new_description: str | None, limit: int = 4000) -> str:
    """Unified diff of two descriptions (what an admin needs to judge a drift)."""
    old = (old_description or "").splitlines() or [""]
    new = (new_description or "").splitlines() or [""]
    lines = list(difflib.unified_diff(old, new, "pinned", "current", lineterm="", n=2))
    text = "\n".join(lines) if lines else "(description unchanged)"
    return text if len(text) <= limit else text[:limit] + "\n…[truncated]"


def schema_changed(old_schema: dict[str, Any] | None, new_schema: dict[str, Any] | None) -> bool:
    return canonical_json(old_schema or {}) != canonical_json(new_schema or {})
