"""SEC-MCP-02 `mcp_protocol`: MCP protocol-level checks (concept §9 "MCP integrity").

At `mcp_initialize` (any server-bound MCP message that is not a tool call: initialize, resources/prompts methods,
server-initiated requests) and at `tool_call` (only for MCP tools, `payload.server` set):

    server allowlist        the server must exist in `policy.mcp_servers` with `allowed: true`
    grants                  the principal must be granted the server / tool. The proxy resolves grants (no I/O
                            here, the control budget is 10 ms) and passes `ctx.attributes["mcp_access"]`
                            (`{"server": {...}, "tool": {...}}`, each `{allowed, rule_id, reason}`)
    sampling denied         `sampling/createMessage` (and other `deny_methods`) from a server: no origin
                            authentication, it can inject user-role text
    header/body agreement   MCP 2026-07-28 `Mcp-Method` / `Mcp-Name` vs the JSON-RPC body
    OAuth metadata URLs     https only, no shell metacharacters (CVE-2025-6514)
    origin binding          `policy.mcp_servers.<id>.origin` must equal the origin the proxy actually reached
    server text             `instructions` / `serverInfo` text is scanned like a tool description
    tool calls              the tool must be declared in `policy.tools` for that server (unknown tools are
                            hidden by default) and must not be quarantined / pending approval
                            (`ctx.attributes["mcp_tool_status"]`, reported under rule SEC-MCP-01)

Params: `deny_methods`, `allow_http_localhost`, and the proxy-side knobs `canaries` (values that must never
leave through a tool result: redacted + incident) and `max_result_bytes`.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, InspectionPoint, Phase
from acl.contracts.decision import Finding, Verdict
from acl.contracts.inspection import InspectionContext, McpPayload, ToolCallPayload
from acl.controls.base import Control, register_control
from acl.controls.mcp import rules
from acl.controls.mcp.scan import scan_text

RULE_PINNING = "SEC-MCP-01"
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$")


class McpProtocolParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deny_methods: list[str] = Field(default_factory=lambda: ["sampling/createMessage", "elicitation/create"])
    allow_http_localhost: bool = False
    canaries: list[str] = Field(default_factory=list)
    max_result_bytes: int = Field(default=2_000_000, ge=1_000, le=64_000_000)


def _server_text(params: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    instr = params.get("instructions")
    if isinstance(instr, str):
        texts.append(instr)
    info = params.get("server_info")
    if isinstance(info, dict):
        texts.extend(str(info[k]) for k in ("name", "title", "description") if isinstance(info.get(k), str))
    return texts


@register_control
class McpProtocolControl(Control):
    type = "mcp_protocol"
    phase = Phase.deterministic
    Params = McpProtocolParams
    cacheable = False  # depends on proxy-supplied attributes

    def _server_problems(self, ctx: InspectionContext, server: str) -> list[rules.Violation]:
        policy = self.deps.get("policy")
        cfg = policy.mcp_servers.get(server) if policy is not None else None
        if cfg is None or not cfg.allowed:
            return [rules.Violation("MCP_SERVER_NOT_ALLOWED", "MCP server is not on the allowlist")]
        access = (ctx.attributes.get("mcp_access") or {}).get("server")
        if isinstance(access, dict) and access.get("allowed") is False:
            return [rules.Violation("MCP_SERVER_NOT_GRANTED", str(access.get("reason") or "MCP server not granted"))]
        return []

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: McpProtocolParams = self.params  # type: ignore[assignment]
        payload = ctx.payload
        violations: list[rules.Violation] = []
        rule_override: dict[str, str] = {}

        if ctx.point == InspectionPoint.mcp_initialize and isinstance(payload, McpPayload):
            violations += self._server_problems(ctx, payload.server)
            if payload.method in p.deny_methods or payload.method.startswith("sampling/"):
                violations.append(
                    rules.Violation("MCP_SAMPLING_DENIED", f"server-initiated '{payload.method}' is denied by policy")
                )
            violations += rules.check_headers(payload.method, payload.params, payload.headers)
            violations += rules.check_oauth(payload.params, allow_http_localhost=p.allow_http_localhost)
            policy = self.deps.get("policy")
            cfg = policy.mcp_servers.get(payload.server) if policy is not None else None
            observed = payload.params.get("observed_origin")
            if cfg is not None and cfg.origin and isinstance(observed, str) and observed != cfg.origin:
                violations.append(rules.Violation("MCP_ORIGIN_MISMATCH", "server origin differs from the bound origin"))
            for text in _server_text(payload.params):
                if any(h.kind == "poisoned" for h in scan_text(text)):
                    violations.append(
                        rules.Violation("MCP_INSTRUCTIONS_POISONED", "server instructions contain hidden directives")
                    )
                    break
        elif ctx.point == InspectionPoint.tool_call and isinstance(payload, ToolCallPayload) and payload.server:
            violations += self._server_problems(ctx, payload.server)
            policy = self.deps.get("policy")
            tool = policy.tools.get(payload.tool) if policy is not None else None
            if tool is None or tool.server != payload.server:
                violations.append(rules.Violation("MCP_UNKNOWN_TOOL", "tool is not declared for this MCP server"))
            access = (ctx.attributes.get("mcp_access") or {}).get("tool")
            if isinstance(access, dict) and access.get("allowed") is False:
                violations.append(
                    rules.Violation("MCP_TOOL_NOT_GRANTED", str(access.get("reason") or "tool not granted"))
                )
                granted_by = access.get("rule_id")
                if isinstance(granted_by, str) and _RULE_ID.match(granted_by):
                    rule_override["MCP_TOOL_NOT_GRANTED"] = granted_by  # SEC-TOOL-01 or the org lock that denied it
            status = ctx.attributes.get("mcp_tool_status")
            if status in ("quarantined", "pending_approval"):
                violations.append(rules.Violation("MCP_TOOL_QUARANTINED", f"tool is {status} until re-approved"))
        else:
            return self.verdict()

        if not violations:
            return self.verdict()

        def rule_of(v: rules.Violation) -> str:
            if v.code == "MCP_TOOL_QUARANTINED":
                return RULE_PINNING
            return rule_override.get(v.code, self.id)

        return self.verdict(
            action=Action.block,
            final=True,
            rule_ids=list(dict.fromkeys(rule_of(v) for v in violations)),
            findings=[Finding(entity_type=v.code, rule_id=rule_of(v)) for v in violations],
            reason="; ".join(dict.fromkeys(v.reason for v in violations)),
        )
