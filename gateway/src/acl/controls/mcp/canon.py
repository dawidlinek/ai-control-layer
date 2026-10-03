"""Canonical MCP tool form and manifest pin (concept §9, "MCP integrity").

The pin of a tool is

    sha256( name \\0 description \\0 canonical_json(inputSchema) )        (lower-case hex)

where `canonical_json` sorts keys and uses compact separators (`acl.contracts.canonical.canonical_json`
rules, UTF-8, no ASCII escaping). NUL separators keep the three parts unambiguous. A missing description
counts as the empty string and a missing schema as `{}`. Admins can reproduce a pin for `tools.<id>.schema_pin`
with `python -c "from acl.controls.mcp.canon import tool_hash; print(tool_hash(name, desc, schema))"`.
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
    """Pin of a raw MCP `Tool` object (`name`, `description`, `inputSchema`)."""
    schema = tool.get("inputSchema")
    return tool_hash(
        str(tool.get("name") or ""),
        tool.get("description") if isinstance(tool.get("description"), str) else "",
        schema if isinstance(schema, dict) else {},
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
