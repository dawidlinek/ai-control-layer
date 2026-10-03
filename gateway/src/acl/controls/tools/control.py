"""SEC-TOOL-01 `tool_policy`: tool authorisation, tiers and argument checkers at the `tool_call` point (concept §9).

Deterministic and fail closed. Evaluation order (the first failing step that blocks wins; approvals accumulate):

  1. the tool must exist in the policy catalogue (`tools`); unknown → block (`SEC-TOOL-01.UNKNOWN_TOOL`)
  2. grant check `access.check_tool` (org locks, group policy, DB grants incl. deny) → block, rule id of the check
  3. monotonic confinement: `session.allowed_tools` (narrowed by `downgrade`) never widens → block `.CONFINED`
  4. preset `tool_mode: allowlist` (strict/paranoid): only tools explicitly listed for the principal → `.ALLOWLIST`
  5. tier (group `ToolGrant.tier` override, else `ToolDef.default_tier`):
        deny → block; confirm → require_approval unless an active time-boxed elevation exists;
        must → "required in this context": enforced as allow + recorded (`outputs["tool_tier"]`), the plan/obligation
        itself is task-scoped policy (SEC-PLAN-01); allow → continue
  6. argument validation: pinned schema (policy `arguments_schema` or `ctx.attributes["tool_input_schema"]` set by the
     MCP proxy); unknown argument fields are ALWAYS rejected (parasitic parameters)
  7. checkers (`ToolDef.checkers` + group constraints): path, command, url, recipient, sql, package
  8. preset `approval_on_writes` (paranoid): irreversible / filesystem-write tools → require_approval

Blocks are `final`. Approval reasons from this control (confirm tier, unlisted shell command, writes) are cleared by an
active elevation; deny classes, protected paths and every block are never relaxed. Raw argument values never go into
verdicts: findings carry salted hashes only.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from acl.contracts.common import Action, ToolTier
from acl.contracts.decision import Decision, Finding, Verdict
from acl.contracts.inspection import InspectionContext, ToolCallPayload, ToolIntent
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.normalise.intent import COMMAND_KEYS, build_intent
from acl.controls.normalise.scan import hash_value, value_salt
from acl.controls.tools import checkers as chk
from acl.controls.tools.catalogue import (
    EffectiveGrant,
    apply_downgrade,
    effective_grant,
    is_write_tool,
)
from acl.controls.tools.commands import analyze_command
from acl.controls.tools.paths import (
    canonical,
    check_path,
    classify_sensitive,
    glob_match,
    is_persistence_path,
    within,
    workspace_root,
)
from acl.identity.access import RULE_TOOL, DefaultAccessResolver, expand_groups
from acl.policy.models import ArgChecker, ControlConfig, Policy, ToolDef

log = logging.getLogger(__name__)


class ToolPolicyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    missing_service: Literal["block", "policy_only"] = "block"
    """When the `access` service is not registered: `block` (fail closed) or resolve from group policy + org locks."""
    require_schema: bool = False
    """Block MCP tools (catalogue `server` set) that have no pinned schema from either source."""
    safe_commands: list[str] = Field(default_factory=list)
    """Extra argv prefixes (e.g. `git fetch`) treated as safe read-only shell commands."""
    sql_dialect: str = "postgres"
    max_arg_bytes: int = Field(default=256_000, ge=1024)
    """Arguments larger than this are rejected (cheap guard against parser abuse)."""


@dataclass
class _Hit:
    code: str
    reason: str
    field: str = ""
    value: str | None = None


@dataclass
class _Outcome:
    blocks: list[_Hit] = field(default_factory=list)
    approvals: list[_Hit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def block(self, code: str, reason: str, field: str = "", value: str | None = None) -> None:
        self.blocks.append(_Hit(code, reason, field, value))

    def approve(self, code: str, reason: str, field: str = "", value: str | None = None) -> None:
        self.approvals.append(_Hit(code, reason, field, value))


def _nodes(arguments: dict[str, Any], dotted: str) -> list[Any]:
    cur: list[Any] = [arguments]
    for part in dotted.split("."):
        nxt: list[Any] = []
        for item in cur:
            if isinstance(item, dict) and part in item:
                nxt.append(item[part])
            elif isinstance(item, list):
                nxt.extend(x[part] for x in item if isinstance(x, dict) and part in x)
        cur = nxt
    return cur


def _command_values(arguments: dict[str, Any], dotted: str) -> list[str]:
    """Shell commands at a dot path, plus any other top-level command-like key (`cmd`, `script`, ...): a client or an
    MCP server may honour an alias the catalogue does not name. An argv list is ONE command, not several."""
    nodes = _nodes(arguments, dotted)
    nodes += [v for k, v in arguments.items() if k.lower() in COMMAND_KEYS and k != dotted and v not in nodes]
    out: list[str] = []
    for item in nodes:
        if isinstance(item, str):
            cmd = item
        elif isinstance(item, list) and item and all(isinstance(x, str) for x in item):
            cmd = shlex.join(item)
        else:
            continue
        if cmd not in out:
            out.append(cmd)
    return out


def _lookup(arguments: dict[str, Any], dotted: str) -> list[str]:
    """String values at a dot path (lists are flattened; non-strings are ignored)."""
    out: list[str] = []
    for item in _nodes(arguments, dotted):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, list):
            out.extend(x for x in item if isinstance(x, str))
    return out


@register_control
class ToolPolicyControl(Control):
    type = "tool_policy"
    Params = ToolPolicyParams
    cacheable = False  # depends on principal, grants, session and elevations

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)

    # ------------------------------------------------------------ services

    def _resolver(self, policy: Policy) -> Any:
        access = self.deps.get("access")
        if access is not None:
            return access
        if self.params.missing_service == "policy_only":  # type: ignore[attr-defined]
            version = self.deps.get("policy_version", "unknown")
            return DefaultAccessResolver(lambda: (policy, version))
        return None

    def _exfil_domains(self, policy: Policy) -> list[str]:
        out: list[str] = []
        for c in policy.controls:
            if c.type == "url_egress" and c.enabled:
                out.extend(str(d) for d in c.params.get("allow_domains", []))
        return out

    # ------------------------------------------------------------ inspect

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: ToolPolicyParams = self.params  # type: ignore[assignment]
        payload = ctx.attributes.get("payload")
        if not isinstance(payload, ToolCallPayload):
            payload = ctx.payload
        if not isinstance(payload, ToolCallPayload):
            return self.verdict(reason="not a tool call")
        policy: Policy | None = self.deps.get("policy")
        if policy is None:
            return self._deny(_Outcome(), "UNAVAILABLE", "tool policy is not loaded (failing closed)")

        tool_id = payload.tool
        tool = policy.tools.get(tool_id)  # type: ignore[call-overload]
        if tool is None:
            return self._deny(_Outcome(), "UNKNOWN_TOOL", "tool is not in the policy catalogue")
        if payload.server and tool.server and payload.server != tool.server:
            return self._deny(
                _Outcome(), "SERVER_MISMATCH", "tool call names a different MCP server than the catalogue"
            )

        resolver = self._resolver(policy)
        if resolver is None:
            return self._deny(_Outcome(), "UNAVAILABLE", "tool access cannot be decided: access service missing")
        check = await resolver.check_tool(ctx.principal, tool_id)
        if not check.allowed:
            rules = [self.id] + [r for r in [check.rule_id or RULE_TOOL] if r != self.id]
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=rules,
                reason=check.reason,
                outputs={"tool_tier": ToolTier.deny.value},
            )

        out = _Outcome()
        if ctx.session.allowed_tools is not None and tool_id not in ctx.session.allowed_tools:
            out.block("CONFINED", "tool is outside the session's narrowed tool set (monotonic confinement)")

        grant = effective_grant(policy, ctx.principal.groups, tool_id, tool)
        settings = self.preset_settings(ctx)
        if (
            settings is not None
            and settings.tool_mode == "allowlist"
            and not grant.explicit
            and not await self._explicitly_granted(resolver, ctx, tool_id)
        ):
            out.block("ALLOWLIST", "preset requires the tool to be explicitly granted (tool allowlist)")

        tier = grant.tier
        if tier == ToolTier.deny:
            out.block("TIER_DENY", "tool tier is deny for this principal")
        elif tier == ToolTier.confirm:
            out.approve("CONFIRM", "tool is in the confirm tier: human approval required")
        elif tier == ToolTier.must:
            out.notes.append("tier=must (required in this context; enforced as allow, recorded)")

        if out.blocks:  # no point running checkers on a call that is already denied; keep the audit trail short
            return self._compose(out, None)

        if len(repr(payload.arguments)) > p.max_arg_bytes:
            out.block("ARGS_TOO_LARGE", "tool arguments exceed the size limit")
            return self._compose(out, None)

        self._validate_schema(ctx, payload, tool, out)
        try:
            intent = ctx.attributes.get("intent")
            if not isinstance(intent, ToolIntent):
                intent = build_intent(payload)
        except (ValueError, TypeError, RecursionError):
            out.block("INTENT", "tool call could not be normalised (failing closed)")
            return self._compose(out, None)

        for checker in tool.checkers:
            self._run_checker(checker, payload, intent, grant, ctx, policy, out)
        # The client runs the ORIGINAL arguments, the normaliser may have rewritten them (NFKC, hidden characters,
        # template tokens): check what will really execute as well, so a rewrite can only ever add findings.
        raw = ctx.payload
        if isinstance(raw, ToolCallPayload) and raw.arguments != payload.arguments:
            try:
                raw_intent = build_intent(raw)
            except (ValueError, TypeError, RecursionError):
                out.block("INTENT", "tool call could not be normalised (failing closed)")
                return self._compose(out, None)
            for checker in tool.checkers:
                self._run_checker(checker, raw, raw_intent, grant, ctx, policy, out)

        if settings is not None and settings.approval_on_writes and is_write_tool(tool):
            out.approve("WRITE_APPROVAL", "preset requires approval for writes / irreversible tools")

        outputs: dict[str, Any] = {"tool_tier": tier.value}
        if "intent" not in ctx.attributes:
            outputs["intent"] = intent  # packages/paths for later phases when the normaliser did not publish one
        if out.approvals and not out.blocks and await self._elevated(ctx, tool_id):
            out.approvals.clear()
            out.notes.append("approval waived by an active time-boxed elevation")
        return self._compose(out, outputs)

    # ------------------------------------------------------------ steps

    async def _elevated(self, ctx: InspectionContext, tool_id: str) -> bool:
        approvals = self.deps.get("approvals")
        if approvals is None:
            return False
        until = await approvals.elevation(ctx.session_id, tool_id)
        return until is not None

    async def _explicitly_granted(self, resolver: Any, ctx: InspectionContext, tool_id: str) -> bool:
        effective = getattr(resolver, "effective_access", None)
        if effective is None:
            return False
        try:
            access = await effective(ctx.principal)
        except Exception:
            log.exception("effective access lookup failed")
            return False
        return any(
            i.resource_type.value == "tool" and i.resource == tool_id and i.effect == "allow" for i in access.items
        )

    def _validate_schema(self, ctx: InspectionContext, payload: ToolCallPayload, tool: ToolDef, out: _Outcome) -> None:
        p: ToolPolicyParams = self.params  # type: ignore[assignment]
        schema = tool.arguments_schema or ctx.attributes.get("tool_input_schema")
        if not isinstance(schema, dict) or not schema:
            if p.require_schema and tool.server:
                out.block("NO_SCHEMA", "no pinned argument schema is available for this MCP tool")
            return
        for v in chk.check_arguments(payload.arguments, schema):
            out.block(v.code, v.reason, v.field, v.value)

    def _run_checker(
        self,
        checker: ArgChecker,
        payload: ToolCallPayload,
        intent: ToolIntent,
        grant: EffectiveGrant,
        ctx: InspectionContext,
        policy: Policy,
        out: _Outcome,
    ) -> None:
        values = _lookup(payload.arguments, checker.field)
        # The workspace comes from the client's trusted context only. A model-supplied `workdir` may move the working
        # directory (and is itself path-checked) but can never redefine what "inside the workspace" means.
        ws = workspace_root(payload.workspace_root, payload.cwd)
        workdir = _lookup(payload.arguments, "workdir")
        cwd_s = canonical(workdir[0], payload.cwd, payload.workspace_root) if workdir else payload.cwd
        kind = checker.type
        if kind == "path":
            self._check_paths(checker, values, intent, payload, cwd_s, ws, grant, out)
        elif kind == "command":
            self._check_commands(
                checker, _command_values(payload.arguments, checker.field), payload, cwd_s, ws, grant, out
            )
        elif kind == "url":
            self._check_urls(checker, values, intent, grant, ctx, policy, out)
        elif kind == "recipient":
            recips = chk.extract_recipients([*values, *intent.recipients])
            for v in chk.check_recipients(
                values,
                recips,
                allow=grant.recipients_allow,
                require_allowlist=bool(checker.params.get("require_allowlist", False)),
                field=f"arguments.{checker.field}",
            ):
                out.block(v.code, v.reason, v.field, v.value)
        elif kind == "sql":
            self._check_sql(checker, values, intent, ctx, out)
        elif kind == "package" and not intent.packages and values and checker.params.get("require_packages", True):
            out.approve("PACKAGE_UNVERIFIABLE", "install target could not be resolved to a package/version")

    def _check_paths(
        self,
        checker: ArgChecker,
        values: list[str],
        intent: ToolIntent,
        payload: ToolCallPayload,
        cwd: str | None,
        ws: str | None,
        grant: EffectiveGrant,
        out: _Outcome,
    ) -> None:
        workspace_only = bool(checker.params.get("workspace_only", False))
        write = str(checker.params.get("access", "")).lower() == "write"
        for raw in dict.fromkeys([*values, *intent.paths]):
            if write and is_persistence_path(canonical(raw, cwd, payload.workspace_root)):
                out.approve(
                    "PATH_PERSISTENCE",
                    "write to a hook / CI / startup / agent-instruction file",
                    f"arguments.{checker.field}",
                    raw,
                )
            for v in check_path(
                raw,
                cwd=cwd,
                root=payload.workspace_root,
                workspace_only=workspace_only,
                allow=grant.path_allow,
                deny=grant.path_deny,
                workspace=ws,
            ):
                out.block(f"PATH_{v.code}", v.reason, f"arguments.{checker.field}", raw)

    def _check_commands(
        self,
        checker: ArgChecker,
        values: list[str],
        payload: ToolCallPayload,
        cwd: str | None,
        ws: str | None,
        grant: EffectiveGrant,
        out: _Outcome,
    ) -> None:
        p: ToolPolicyParams = self.params  # type: ignore[assignment]
        extra = (*p.safe_commands, *[str(c) for c in checker.params.get("safe_commands", [])])
        fld = f"arguments.{checker.field}"
        if cwd and cwd != payload.cwd:  # the model moved the working directory with `workdir`
            cls = classify_sensitive(cwd)
            if cls is not None:
                out.block("CMD_SENSITIVE_PATH", f"working directory is a protected location ({cls})", fld, cwd)
            elif ws is None or not within(cwd, ws):
                out.approve("CMD_OUTSIDE_WORKSPACE", "working directory is outside the workspace", fld, cwd)
        for raw in values:
            a = analyze_command(raw, cwd=cwd, root=payload.workspace_root, extra_safe=extra, workspace=ws)
            for d in a.deny:
                out.block(f"CMD_{d.code}", d.reason, fld, raw)
            if grant.path_deny:
                for tok in a.paths:
                    cp = canonical(tok, cwd, payload.workspace_root)
                    if any(glob_match(g, cp, ws) for g in grant.path_deny):
                        out.block("CMD_PATH_DENIED", "command touches a path denied for this group", fld, raw)
                        break
            for code in a.approval[:4]:
                out.approve(f"CMD_{code}", "shell command is not on the safe list: approval required", fld, raw)

    def _check_urls(
        self,
        checker: ArgChecker,
        values: list[str],
        intent: ToolIntent,
        grant: EffectiveGrant,
        ctx: InspectionContext,
        policy: Policy,
        out: _Outcome,
    ) -> None:
        mode = str(checker.params.get("allowlist", "group"))
        allow: list[str] | None
        if grant.domains_allow:
            allow = list(grant.domains_allow)
        elif mode == "group_or_exfil":
            allow = self._exfil_domains(policy)
        else:
            allow = None  # no allowlist configured for this principal: scheme/credential/metadata rules only
        urls = list(dict.fromkeys([*values, *intent.urls]))
        for u in urls:
            for v in chk.check_url(
                u,
                allow_domains=allow,
                field=f"arguments.{checker.field}",
                block_private=bool(checker.params.get("block_private", False)),
            ):
                out.block(v.code, v.reason, v.field, v.value)

    def _check_sql(
        self, checker: ArgChecker, values: list[str], intent: ToolIntent, ctx: InspectionContext, out: _Outcome
    ) -> None:
        p: ToolPolicyParams = self.params  # type: ignore[assignment]
        statements = [*values, *([intent.sql] if intent.sql and intent.sql not in values else [])]
        scope = chk.scope_from_params(checker.params, expand_groups(ctx.principal.groups))
        dialect = str(checker.params.get("dialect", p.sql_dialect))
        for sql in statements:
            for v in chk.check_sql(sql, scope, read_only=bool(checker.params.get("read_only", True)), dialect=dialect):
                out.block(v.code, v.reason, f"arguments.{checker.field}", v.value or sql)

    # ------------------------------------------------------------ verdicts

    def _deny(self, out: _Outcome, code: str, reason: str) -> Verdict:
        out.block(code, reason)
        return self._compose(out, None)

    def _compose(self, out: _Outcome, outputs: dict[str, Any] | None) -> Verdict:
        def hits(items: list[_Hit]) -> tuple[list[str], list[Finding]]:
            rules: list[str] = []
            findings: list[Finding] = []
            for h in items:
                rid = f"{self.id}.{h.code}"
                if rid not in rules:
                    rules.append(rid)
                findings.append(
                    Finding(
                        entity_type=h.code,
                        field=h.field,
                        value_hash=hash_value(self._salt, h.value) if h.value else None,
                        rule_id=rid,
                    )
                )
            return rules, findings

        if out.blocks:
            rules, findings = hits(out.blocks)
            reason = "; ".join(dict.fromkeys(h.reason for h in out.blocks))[:500]
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=[self.id, *rules],
                findings=findings,
                reason=reason,
                outputs=outputs or {},
            )
        if out.approvals:
            rules, findings = hits(out.approvals)
            reason = "; ".join(dict.fromkeys(h.reason for h in out.approvals))[:500]
            return self.verdict(
                action=Action.require_approval,
                rule_ids=[self.id, *rules],
                findings=findings,
                reason=reason,
                outputs=outputs or {},
            )
        return self.verdict(reason="; ".join(out.notes) or None, outputs=outputs or {})

    # ------------------------------------------------------------ commit

    async def commit(self, ctx: InspectionContext, decision: Decision) -> None:
        await apply_downgrade(self.deps, ctx, decision)
