"""SEC-MCP-01 `mcp_pinning`: tools/list integrity (concept §9 "MCP integrity").

Evaluated at `mcp_tools_list` on an `McpPayload` whose `tools` are the (raw) tool descriptors a server
announced. Per tool the control flags

    drift         `sha256(name, description, inputSchema)` differs from the pin (`ctx.attributes["mcp_pins"]`,
                  supplied by the proxy from its database) -> rug pull
    schema_pin    the policy's `tools.<id>.schema_pin` does not match the announced tool
    poisoned      hidden/imperative instructions, steering to other tools, credential paths, exfil instructions,
                  invisible characters, Base64 blobs, HTML comments, oversized text, odd names (see `scan.py`)
    collision     the name is already declared by ANOTHER server (policy catalogue or `mcp_other_tools` from the
                  database) or appears twice in the list: the later one shadows the earlier -> flagged

A tool whose pin matches and whose status is `pinned` is not re-scanned (the admin approved exactly this hash).
The verdict is `block` (the proxy quarantines/hides the flagged tools and serves the rest; `on_drift: monitor`
only records) and publishes `outputs["mcp_flags"] = {tool_name: [{kind, detail, rule}]}` for the proxy.
Findings carry the tool index in `field` (`tools[i].description`), never description text.

The control also applies to cases without any database state: `mcp_pins` / `mcp_other_tools` are optional.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Finding, Verdict
from acl.contracts.inspection import InspectionContext, McpPayload
from acl.controls.base import Control, register_control
from acl.controls.mcp.canon import normalise_name, tool_hash
from acl.controls.mcp.catalog import catalog_for
from acl.controls.mcp.scan import scan_tool

KIND_ENTITY = {
    "drift": "MCP_TOOL_DRIFT",
    "schema_pin": "MCP_SCHEMA_PIN_MISMATCH",
    "poisoned": "MCP_TOOL_POISONED",
    "invisible_chars": "MCP_TOOL_HIDDEN_CHARS",
    "base64_blob": "MCP_TOOL_BASE64",
    "oversized": "MCP_TOOL_OVERSIZED",
    "invalid_name": "MCP_TOOL_NAME",
    "collision": "MCP_TOOL_COLLISION",
}
# kinds that make a tool `quarantined`; `collision` alone only needs approval (`pending_approval`)
HARD_KINDS = frozenset(KIND_ENTITY) - {"collision"}


class McpPinningParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_drift: Literal["quarantine", "monitor"] = "quarantine"
    scan_descriptions: bool = True
    check_collisions: bool = True
    max_description_len: int = Field(default=4000, ge=100, le=100_000)
    base64_min_len: int = Field(default=40, ge=16, le=4096)
    recheck_interval_s: float = Field(
        default=2.0,
        ge=0.0,
        le=3600.0,
        description="Proxy: re-list the upstream before a call if the pin check is older.",
    )


@register_control
class McpPinningControl(Control):
    type = "mcp_pinning"
    phase = Phase.deterministic
    Params = McpPinningParams
    cacheable = False  # depends on database state passed in ctx.attributes

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        payload = ctx.payload
        if ctx.point != InspectionPoint.mcp_tools_list or not isinstance(payload, McpPayload) or not payload.tools:
            return self.verdict()
        p: McpPinningParams = self.params  # type: ignore[assignment]
        policy = self.deps.get("policy")
        catalog = catalog_for(policy) if policy is not None else None
        pins: dict[str, Any] = ctx.attributes.get("mcp_pins") or {}
        others: dict[str, str] = ctx.attributes.get("mcp_other_tools") or {}
        duplicates = set(ctx.attributes.get("mcp_duplicate_names") or ())  # names the proxy saw announced twice

        flags: dict[str, list[dict[str, str]]] = {}
        findings: list[Finding] = []
        seen: dict[str, int] = {}
        drift_only = True

        def flag(index: int, name: str, kind: str, detail: str) -> None:
            nonlocal drift_only
            entry = {"kind": kind, "detail": detail, "rule": self.id}
            bucket = flags.setdefault(name, [])
            if entry not in bucket:
                bucket.append(entry)
                if kind != "drift":
                    drift_only = False
                findings.append(
                    Finding(entity_type=KIND_ENTITY[kind], field=f"tools[{index}].description", rule_id=self.id)
                )

        for i, tool in enumerate(payload.tools):
            h = tool_hash(tool.name, tool.description, tool.input_schema)
            norm = normalise_name(tool.name)
            pin = pins.get(tool.name)
            pinned_ok = bool(pin and pin.get("status") == "pinned" and pin.get("pinned_hash") == h)

            if norm in seen or tool.name in duplicates:
                flag(i, tool.name, "collision", "duplicate_name_in_list")
            seen.setdefault(norm, i)

            declared = catalog.resolve(payload.server, tool.name) if catalog is not None else None
            if declared is not None and declared[1].schema_pin and declared[1].schema_pin != h:
                flag(i, tool.name, "schema_pin", "policy_schema_pin_mismatch")
            if pin and pin.get("pinned_hash") and pin.get("pinned_hash") != h:
                flag(i, tool.name, "drift", "manifest_hash_changed")
            if pinned_ok:
                continue
            if p.scan_descriptions:
                for hit in scan_tool(
                    tool.name,
                    tool.description,
                    tool.input_schema,
                    max_len=p.max_description_len,
                    base64_min_len=p.base64_min_len,
                ):
                    flag(i, tool.name, hit.kind, f"{hit.where}:{hit.detail}")
            if p.check_collisions and declared is None:
                owner = catalog.other_owner(payload.server, tool.name) if catalog is not None else None
                if owner is not None:
                    flag(i, tool.name, "collision", f"declared_by_server:{owner}")
                elif norm in others and not others[norm].startswith(f"{payload.server}:"):
                    flag(i, tool.name, "collision", f"seen_on_server:{others[norm].split(':', 1)[0]}")

        if not flags:
            return self.verdict()
        monitor_only = drift_only and p.on_drift == "monitor"
        counts: dict[str, int] = {}
        for entries in flags.values():
            for k in {e["kind"] for e in entries}:
                counts[k] = counts.get(k, 0) + 1
        summary = ", ".join(f"{k}={n}" for k, n in sorted(counts.items()))
        return self.verdict(
            action=Action.monitor if monitor_only else Action.block,
            rule_ids=[self.id],
            findings=findings,
            reason=f"{len(flags)} MCP tool(s) flagged on server '{payload.server}' ({summary})",
            outputs={"mcp_flags": flags},
        )
