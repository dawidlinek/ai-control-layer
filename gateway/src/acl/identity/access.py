"""Access resolution: org locks → group policy → DB grants (concept §7.1, §9, §11).

Public surface (stable; other phases code against it):

    AccessCheck, AccessResolver (Protocol)

Resolution rules
----------------
1. **Org locks** (`policy.org_locks`) are evaluated first and cannot be exceeded by anything below:
   `deny_resource` removes matching resources (except for listed groups); `data_class_tier` removes
   data classes from models whose connector tier is not allowed for them.
2. **Group policy** (`groups.<g>.models / skills / tools / mcp_servers`, `max_external_data_class`)
   grants access. A principal inherits the policy of the parent groups of every group it is in
   (`agents/research-bot` also gets `agents`).
3. **DB grants** (user or group subject, with expiry): `allow` extends access (within 1), `deny` removes
   it. Deny always beats allow; expired or revoked grants are ignored.

Naming: a grant of a concrete model id also lets the principal use that model's aliases (same
destination); a grant of an alias only grants the alias. A deny on an id or alias blocks every name
that leads to the same model. `auto`-style (non-fixed) aliases expand to the routing targets.
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol

from acl.contracts.admin import EffectiveAccess, EffectiveAccessItem, Grant, GrantConstraints
from acl.contracts.common import (
    DATA_CLASS_ORDER,
    ConnectorTier,
    DataClass,
    GrantResourceType,
    Preset,
)
from acl.contracts.inspection import Principal
from acl.identity.db_models import utcnow
from acl.identity.grants import normalise_resource
from acl.policy.models import DataClassTierLock, DenyResourceLock, ModelEntry, Policy

log = logging.getLogger(__name__)

RULE_MODEL = "SEC-MODEL-01"
RULE_TOOL = "SEC-TOOL-01"
_PRESET_RANK = {p: i for i, p in enumerate(Preset)}
_MODEL_FAMILY = (
    GrantResourceType.model,
    GrantResourceType.alias,
    GrantResourceType.connector,
    GrantResourceType.skill,
)


@dataclass(frozen=True)
class AccessCheck:
    allowed: bool
    rule_id: str | None
    reason: str
    source: str  # "group:<g>" | "grant:<id>" | "org_lock:<id>" | "default"


class AccessUnavailable(RuntimeError):
    """No policy is loaded yet (engine not built): access cannot be decided, callers must fail closed."""


class AccessResolver(Protocol):
    async def check_model(self, principal: Principal, name: str) -> AccessCheck:
        """Model id | alias | `skill/<x>`. Deny rule id is `SEC-MODEL-01` or the org lock id."""
        ...

    async def usable_models(self, principal: Principal) -> dict[str, list[DataClass]]:
        """Concrete enabled model id → data classes this principal may send there."""
        ...

    async def visible_names(self, principal: Principal) -> list[str]:
        """Names for a personalised `/v1/models`: allowed aliases, model ids, skills."""
        ...

    async def effective_preset(self, principal: Principal) -> Preset:
        """Strictest of: group presets (or `global.default_preset` if no group sets one) and grant presets."""
        ...

    async def effective_access(self, principal: Principal) -> EffectiveAccess: ...

    async def check_tool(self, principal: Principal, tool_id: str) -> AccessCheck:
        """Client built-in (`opencode.bash`) or MCP tool (`<server>.<tool>`)."""
        ...


class GrantSource(Protocol):
    async def active_for(self, user_keys: Sequence[str], groups: Sequence[str]) -> list[Grant]: ...

    async def version(self) -> int: ...


class NoGrants:
    """Grant source for policy-only resolution (tests, harness)."""

    async def active_for(self, user_keys: Sequence[str], groups: Sequence[str]) -> list[Grant]:
        return []

    async def version(self) -> int:
        return 0


PolicyView = Callable[[], "tuple[Policy, str] | None"]

# ---------------------------------------------------------------- helpers


def expand_groups(groups: Iterable[str]) -> list[str]:
    """`a/b/c` → [`a/b/c`, `a/b`, `a`] (children inherit the policy of their parents)."""
    out: list[str] = []
    for g in groups:
        g = g.strip("/")
        parts = g.split("/")
        for i in range(len(parts), 0, -1):
            cand = "/".join(parts[:i])
            if cand and cand not in out:
                out.append(cand)
    return out


def grant_keys(principal: Principal) -> tuple[list[str], list[str]]:
    """(user subject keys, expanded groups) used to look up DB grants for a principal."""
    return [k for k in dict.fromkeys([principal.subject, principal.username or ""]) if k], expand_groups(
        principal.groups
    )


def preset_rank(preset: Preset) -> int:
    """monitor < balanced < strict < paranoid."""
    return _PRESET_RANK[preset]


def strictest_preset(cands: Sequence[tuple[Preset, str]]) -> tuple[Preset, str]:
    """The strictest (preset, source); the first one wins a tie."""
    return max(cands, key=lambda c: _PRESET_RANK[c[0]])


def _ordered(classes: Iterable[DataClass]) -> list[DataClass]:
    return sorted(set(classes), key=lambda c: DATA_CLASS_ORDER[c])


def _short(name: str) -> str:
    name = "".join(ch for ch in name if ch.isprintable())
    return name if len(name) <= 80 else name[:77] + "..."


class PolicyIndex:
    """Lookup tables derived from one `Policy` object (rebuilt when the policy object changes)."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.models: dict[str, ModelEntry] = {m.id: m for m in policy.models}
        self.alias_targets: dict[str, tuple[str, ...]] = {}
        self.routed_aliases: set[str] = set()
        for m in policy.models:
            for a in m.aliases:
                self.alias_targets[a] = (m.id,)
        for name, a in policy.aliases.items():
            if a.strategy == "fixed" and a.target:
                self.alias_targets[name] = (a.target,)
            else:
                self.routed_aliases.add(name)
        self.aliases_of: dict[str, list[str]] = {}
        for alias, targets in self.alias_targets.items():
            for t in targets:
                self.aliases_of.setdefault(t, []).append(alias)
        self.by_connector: dict[str, list[str]] = {}
        for m in policy.models:
            self.by_connector.setdefault(m.connector, []).append(m.id)
        r = policy.routing.targets
        routed: list[str] = []
        for slot in (r.local, r.ext_small, r.ext_large, r.degraded):
            routed.extend(self.resolve_ref(slot))
        self.routing_models: tuple[str, ...] = tuple(dict.fromkeys(routed))
        self.tier_locks = [lock for lock in policy.org_locks if isinstance(lock, DataClassTierLock)]
        self.deny_locks = [lock for lock in policy.org_locks if isinstance(lock, DenyResourceLock)]

    def resolve_ref(self, ref: str) -> list[str]:
        """Model id or alias → concrete model ids."""
        if ref in self.models:
            return [ref]
        return list(self.alias_targets.get(ref, ()))

    def tier(self, m: ModelEntry) -> ConnectorTier:
        return self.policy.connectors[m.connector].tier

    def model_enabled(self, m: ModelEntry) -> bool:
        return m.enabled and self.policy.connectors[m.connector].enabled

    def classify(self, ref: str) -> GrantResourceType:
        if ref.startswith("connector:"):
            return GrantResourceType.connector
        if ref in self.policy.skills:
            return GrantResourceType.skill
        if ref in self.models:
            return GrantResourceType.model
        return GrantResourceType.alias

    def expand(self, resource: str) -> list[str]:
        """A granted model-family resource → concrete model ids it reaches."""
        if resource.startswith("connector:"):
            return list(self.by_connector.get(resource.removeprefix("connector:"), ()))
        if resource in self.models:
            return [resource]
        if resource in self.alias_targets:
            return list(self.alias_targets[resource])
        if resource in self.routed_aliases:
            return list(self.routing_models)
        return []

    def model_pairs(self, m: ModelEntry) -> set[tuple[str, str]]:
        pairs = {("model", m.id), ("connector", m.connector)}
        pairs.update(("alias", a) for a in self.aliases_of.get(m.id, ()))
        return pairs

    def lock_hit(
        self, pairs: Iterable[tuple[str, str]], member_groups: Iterable[str], *, skip_conditional: bool = False
    ) -> DenyResourceLock | None:
        """First `deny_resource` lock matching any (resource_type, value) pair, unless the principal is exempt.

        `skip_conditional` ignores locks that have `except_groups` (membership unknown at grant creation).
        """
        member = set(member_groups)
        pairs = list(pairs)
        for lock in self.deny_locks:
            if member.intersection(lock.except_groups) or (skip_conditional and lock.except_groups):
                continue
            rtype = lock.resource_type.value
            for typ, value in pairs:
                if typ == rtype and any(fnmatch.fnmatchcase(value, pat) for pat in lock.resources):
                    return lock
        return None

    def removed_classes(self, m: ModelEntry) -> dict[DataClass, str]:
        """Data classes org locks remove from this model (class → lock id): tier not allowed for the class."""
        tier = self.tier(m)
        removed: dict[DataClass, str] = {}
        for lock in self.tier_locks:
            if tier not in lock.allowed_tiers:
                for c in lock.data_classes:
                    removed.setdefault(c, lock.id)
        return removed


def _pair_key(pair: tuple[str, str]) -> str:
    return f"connector:{pair[1]}" if pair[0] == "connector" else pair[1]


@dataclass(frozen=True)
class _Name:
    """What a requested model name refers to."""

    name: str
    kind: Literal["model", "alias", "routed", "skill", "unknown"]
    models: tuple[ModelEntry, ...] = ()
    pairs: frozenset[tuple[str, str]] = frozenset()
    allow_keys: frozenset[str] = frozenset()

    @property
    def deny_keys(self) -> frozenset[str]:
        return frozenset(_pair_key(p) for p in self.pairs)


@dataclass(frozen=True)
class _Entry:
    effect: Literal["allow", "deny"]
    rtype: GrantResourceType
    resource: str
    origin: Literal["group", "user"]
    ref: str  # group name (policy) or grant id (DB)
    from_grant: bool
    constraints: GrantConstraints = field(default_factory=GrantConstraints)
    expires_at: datetime | None = None
    group_cap: DataClass | None = None  # `max_external_data_class` of the granting policy group

    @property
    def tag(self) -> str:
        return f"grant:{self.ref}" if self.from_grant else f"group:{self.ref}"


# ---------------------------------------------------------------- resolution of one principal


class Resolution:
    def __init__(self, idx: PolicyIndex, principal: Principal, grants: Sequence[Grant], now: datetime) -> None:
        self.idx = idx
        self.policy = idx.policy
        self.principal = principal
        self.now = now
        self.groups = expand_groups(principal.groups)
        self.grants = [g for g in grants if g.revoked_at is None and (g.expires_at is None or g.expires_at > now)]
        self.entries = self._entries()

    # ------------------------------------------------------------ entries

    def _entries(self) -> list[_Entry]:
        idx, out = self.idx, []
        for g in self.groups:
            gp = self.policy.groups.get(g)  # type: ignore[call-overload]
            if gp is None:
                continue
            cap = gp.max_external_data_class
            for ref in gp.models:
                out.append(_Entry("allow", idx.classify(ref), ref, "group", g, False, group_cap=cap))
            for sk in gp.skills:
                out.append(_Entry("allow", GrantResourceType.skill, sk, "group", g, False, group_cap=cap))
            for tool_id, tg in gp.tools.items():
                if tg.tier is not None and tg.tier.value == "deny":
                    continue  # group denies the tool outright: it just isn't granted
                out.append(_Entry("allow", GrantResourceType.tool, tool_id, "group", g, False))
            for server in gp.mcp_servers:
                out.append(_Entry("allow", GrantResourceType.mcp_server, server, "group", g, False))
        for gr in self.grants:
            out.append(
                _Entry(
                    gr.effect,
                    gr.resource_type,
                    normalise_resource(gr.resource_type, gr.resource),
                    "group" if gr.subject_type == "group" else "user",
                    gr.id,
                    True,
                    constraints=gr.constraints,
                    expires_at=gr.expires_at,
                )
            )
        return out

    # ------------------------------------------------------------ locks

    def lock_hit(self, pairs: Iterable[tuple[str, str]]) -> DenyResourceLock | None:
        return self.idx.lock_hit(pairs, self.groups)

    # ------------------------------------------------------------ models

    def name_info(self, name: str) -> _Name:
        idx = self.idx
        if name in self.policy.skills:
            return _Name(name, "skill", pairs=frozenset({("skill", name)}), allow_keys=frozenset({name}))
        if name in idx.models:
            m = idx.models[name]
            return _Name(
                name, "model", (m,), frozenset(idx.model_pairs(m)), frozenset({m.id, f"connector:{m.connector}"})
            )
        if name in idx.alias_targets:
            ms = tuple(idx.models[t] for t in idx.alias_targets[name])
            pairs: set[tuple[str, str]] = {("alias", name)}
            keys = {name}
            for m in ms:
                pairs |= idx.model_pairs(m)
                keys |= {m.id, f"connector:{m.connector}"}
            return _Name(name, "alias", ms, frozenset(pairs), frozenset(keys))
        if name in idx.routed_aliases:
            return _Name(name, "routed", pairs=frozenset({("alias", name)}), allow_keys=frozenset({name}))
        return _Name(name, "unknown")

    def classes_for(self, m: ModelEntry, entry: _Entry) -> tuple[set[DataClass], str | None]:
        """Data classes `entry` lets this principal send to `m`, after org-lock caps (+ the lock that cut)."""
        base = set(m.data_classes)
        if entry.constraints.data_classes is not None:
            base &= set(entry.constraints.data_classes)
        if entry.group_cap is not None and self.idx.tier(m) == ConnectorTier.cloud:
            ceiling = DATA_CLASS_ORDER[entry.group_cap]
            base = {c for c in base if DATA_CLASS_ORDER[c] <= ceiling}
        removed = self.idx.removed_classes(m)
        capped_by = next((removed[c] for c in _ordered(base) if c in removed), None)
        return {c for c in base if c not in removed}, capped_by

    def _model_denied(self, info: _Name) -> tuple[str, str] | None:
        """(source, reason) when an org lock or deny grant removes this name, else None."""
        lock = self.lock_hit(info.pairs)
        if lock is not None:
            return f"org_lock:{lock.id}", f"denied by org lock {lock.id}" + (
                f": {lock.description}" if lock.description else ""
            )
        keys = info.deny_keys
        for e in self.entries:
            if e.effect == "deny" and e.rtype in _MODEL_FAMILY and e.resource in keys:
                return e.tag, f"denied by grant {e.ref}"
        return None

    def check_model(self, name: str) -> tuple[AccessCheck, list[_Entry]]:
        info = self.name_info(name)
        if info.kind == "unknown":
            return AccessCheck(False, RULE_MODEL, f"model '{_short(name)}' is unknown", "default"), []
        denied = self._model_denied(info)
        if denied is not None:
            source, reason = denied
            rule = source.split(":", 1)[1] if source.startswith("org_lock:") else RULE_MODEL
            return AccessCheck(False, rule, reason, source), []
        matching = [e for e in self.entries if e.effect == "allow" and e.rtype in _MODEL_FAMILY]
        matching = [e for e in matching if e.resource in info.allow_keys]
        if not matching:
            return AccessCheck(
                False, RULE_MODEL, f"model '{_short(name)}' is not granted to this principal", "default"
            ), []
        if info.models:
            usable = [m for m in info.models if self.idx.model_enabled(m)]
            if not usable:
                return AccessCheck(False, RULE_MODEL, f"model '{_short(name)}' is disabled", "default"), []
            cut: str | None = None
            any_classes = False
            for e in matching:
                for m in usable:
                    classes, capped_by = self.classes_for(m, e)
                    any_classes = any_classes or bool(classes)
                    cut = cut or capped_by
            if not any_classes:
                if cut is not None:
                    return AccessCheck(
                        False, cut, f"model '{_short(name)}' is not permitted by org lock {cut}", f"org_lock:{cut}"
                    ), []
                return AccessCheck(
                    False, RULE_MODEL, f"no data class of '{_short(name)}' is permitted for this principal", "default"
                ), []
        first = matching[0]
        what = f"group {first.ref}" if not first.from_grant else f"grant {first.ref}"
        return AccessCheck(True, None, f"allowed by {what}", first.tag), matching

    def usable_models(self) -> dict[str, list[DataClass]]:
        allows = [e for e in self.entries if e.effect == "allow" and e.rtype in _MODEL_FAMILY]
        usable: dict[str, set[DataClass]] = {}
        for e in allows:
            for mid in self.idx.expand(e.resource):
                m = self.idx.models.get(mid)
                if m is None or not self.idx.model_enabled(m):
                    continue
                if self._model_denied(self.name_info(mid)) is not None:
                    continue
                classes, _ = self.classes_for(m, e)
                if classes:
                    usable.setdefault(mid, set()).update(classes)
        return {mid: _ordered(c) for mid, c in sorted(usable.items())}

    def visible_names(self) -> list[str]:
        names: list[str] = list(self.idx.models) + list(self.idx.alias_targets) + list(self.idx.routed_aliases)
        names += list(self.policy.skills)
        out = [n for n in dict.fromkeys(names) if self.check_model(n)[0].allowed]
        return sorted(out)

    # ------------------------------------------------------------ preset

    def base_preset(self) -> tuple[Preset, str]:
        """Strictest preset from the policy alone: group presets, or `global.default_preset` if none sets one."""
        group: list[tuple[Preset, str]] = []
        for g in self.groups:
            gp = self.policy.groups.get(g)  # type: ignore[call-overload]
            if gp is not None and gp.preset is not None:
                group.append((gp.preset, f"group:{g}"))
        return strictest_preset(group) if group else (self.policy.global_.default_preset, "default")

    def preset(self) -> tuple[Preset, str]:
        """Strictest of the policy preset (`base_preset`) and every active allow grant's preset constraint.

        A grant (user or group subject) can only tighten the preset, never loosen what the groups set
        (monitor < balanced < strict < paranoid). On a tie the policy source is reported."""
        grants = [
            (g.constraints.preset, f"grant:{g.id}")
            for g in self.grants
            if g.effect == "allow" and g.constraints.preset is not None
        ]
        return strictest_preset([self.base_preset(), *grants])  # type: ignore[list-item]

    # ------------------------------------------------------------ tools

    def _tool_server(self, tool_id: str) -> str | None:
        tool = self.policy.tools.get(tool_id)  # type: ignore[call-overload]
        if tool is not None and tool.server:
            return tool.server
        prefix = tool_id.split(".", 1)[0]
        return prefix if prefix in self.policy.mcp_servers else None

    def check_tool(self, tool_id: str) -> AccessCheck:
        server = self._tool_server(tool_id)
        pairs = {("tool", tool_id)}
        if server:
            pairs.add(("mcp_server", server))
        lock = self.lock_hit(pairs)
        if lock is not None:
            return AccessCheck(
                False,
                lock.id,
                f"denied by org lock {lock.id}" + (f": {lock.description}" if lock.description else ""),
                f"org_lock:{lock.id}",
            )
        if server and not self.policy.mcp_servers[server].allowed:
            return AccessCheck(False, RULE_TOOL, f"MCP server '{_short(server)}' is not on the allowlist", "default")

        def hits(e: _Entry) -> bool:
            if e.rtype == GrantResourceType.tool:
                return e.resource == tool_id
            return e.rtype == GrantResourceType.mcp_server and server is not None and e.resource == server

        for e in self.entries:
            if e.effect == "deny" and hits(e):
                return AccessCheck(False, RULE_TOOL, f"denied by grant {e.ref}", e.tag)
        for e in self.entries:
            if e.effect == "allow" and hits(e):
                what = f"grant {e.ref}" if e.from_grant else f"group {e.ref}"
                return AccessCheck(True, None, f"allowed by {what}", e.tag)
        return AccessCheck(False, RULE_TOOL, f"tool '{_short(tool_id)}' is not granted to this principal", "default")

    def check_mcp_server(self, server: str) -> AccessCheck:
        if server not in self.policy.mcp_servers:
            return AccessCheck(False, RULE_TOOL, f"MCP server '{_short(server)}' is unknown", "default")
        lock = self.lock_hit({("mcp_server", server)})
        if lock is not None:
            return AccessCheck(False, lock.id, f"denied by org lock {lock.id}", f"org_lock:{lock.id}")
        if not self.policy.mcp_servers[server].allowed:
            return AccessCheck(False, RULE_TOOL, f"MCP server '{_short(server)}' is not on the allowlist", "default")
        for e in self.entries:
            if e.effect == "deny" and e.rtype == GrantResourceType.mcp_server and e.resource == server:
                return AccessCheck(False, RULE_TOOL, f"denied by grant {e.ref}", e.tag)
        for e in self.entries:
            if e.effect == "allow" and e.rtype == GrantResourceType.mcp_server and e.resource == server:
                return AccessCheck(True, None, f"allowed by {'grant' if e.from_grant else 'group'} {e.ref}", e.tag)
        for tid, tool in self.policy.tools.items():
            if tool.server == server and self.check_tool(tid).allowed:
                return AccessCheck(True, None, f"a tool of '{_short(server)}' is granted", "default")
        return AccessCheck(
            False, RULE_TOOL, f"MCP server '{_short(server)}' is not granted to this principal", "default"
        )

    def visible_tools(self) -> list[str]:
        return sorted(tid for tid in self.policy.tools if self.check_tool(tid).allowed)

    # ------------------------------------------------------------ effective access

    def effective_access(self, policy_version: str, grants_version: int) -> EffectiveAccess:
        items: list[EffectiveAccessItem] = []
        # org locks that apply to this principal
        member = set(self.groups)
        for lock in self.idx.deny_locks:
            if member.intersection(lock.except_groups):
                continue
            for pat in lock.resources:
                items.append(
                    EffectiveAccessItem(
                        resource_type=lock.resource_type,
                        resource=pat,
                        effect="deny",
                        source="org_lock",
                        source_ref=lock.id,
                    )
                )
        for e in self.entries:
            constraints = e.constraints
            capped: str | None = None
            if e.effect == "allow" and e.rtype in _MODEL_FAMILY:
                reached = [self.idx.models[m] for m in self.idx.expand(e.resource) if m in self.idx.models]
                classes: set[DataClass] = set()
                for m in reached:
                    if self._model_denied(self.name_info(m.id)) is not None:
                        lock = self.lock_hit(self.name_info(m.id).pairs)
                        capped = capped or (lock.id if lock else None)
                        continue
                    cls, cut = self.classes_for(m, e)
                    classes |= cls
                    capped = capped or cut
                if reached:
                    constraints = constraints.model_copy(update={"data_classes": _ordered(classes)})
            elif e.effect == "allow" and e.rtype in (GrantResourceType.tool, GrantResourceType.mcp_server):
                lock = self.lock_hit({(e.rtype.value, e.resource)})
                capped = lock.id if lock else None
            items.append(
                EffectiveAccessItem(
                    resource_type=e.rtype,
                    resource=e.resource,
                    effect=e.effect,
                    source=e.origin,
                    source_ref=e.ref,
                    expires_at=e.expires_at,
                    constraints=constraints,
                    capped_by_lock=capped,
                )
            )
        items.sort(key=lambda i: (i.resource_type.value, i.resource, i.effect, i.source_ref))
        preset, source = self.preset()
        return EffectiveAccess(
            subject=self.principal.subject,
            username=self.principal.username,
            groups=list(self.principal.groups),
            preset=preset,
            preset_source=source,
            items=items,
            budgets=self._budgets(),
            policy_version=policy_version,
            grants_version=str(grants_version),
        )

    def _budgets(self) -> dict[str, dict[str, float]]:
        b = self.policy.budgets

        def limits(obj: object) -> dict[str, float]:
            return {k: float(v) for k, v in obj.model_dump(exclude_none=True).items()}  # type: ignore[attr-defined]

        out = {"org": limits(b.org)}
        for g in self.groups:
            if g in b.groups:  # type: ignore[comparison-overlap]
                out[f"group:{g}"] = limits(b.groups[g])  # type: ignore[index]
        if self.principal.username and self.principal.username in b.users:
            out[f"user:{self.principal.username}"] = limits(b.users[self.principal.username])
        if self.principal.agent_id and self.principal.agent_id in b.agents:
            out[f"agent:{self.principal.agent_id}"] = limits(b.agents[self.principal.agent_id])
        return {k: v for k, v in out.items() if v}


# ---------------------------------------------------------------- resolver implementation


class DefaultAccessResolver:
    """`AccessResolver` over the *current* policy (read at call time) and a grant source."""

    def __init__(
        self,
        policy_view: PolicyView,
        grants: GrantSource | None = None,
        *,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._policy_view = policy_view
        self.grants: GrantSource = grants or NoGrants()
        self._now = now
        self._idx: PolicyIndex | None = None

    def _index(self) -> tuple[PolicyIndex, str]:
        view = self._policy_view()
        if view is None:
            raise AccessUnavailable("no policy is loaded")
        policy, version = view
        if self._idx is None or self._idx.policy is not policy:
            self._idx = PolicyIndex(policy)
        return self._idx, version

    async def _resolve(self, principal: Principal) -> tuple[Resolution, str]:
        idx, version = self._index()
        keys, groups = grant_keys(principal)
        grants = await self.grants.active_for(keys, groups)
        return Resolution(idx, principal, grants, self._now()), version

    async def check_model(self, principal: Principal, name: str) -> AccessCheck:
        res, _ = await self._resolve(principal)
        return res.check_model(name)[0]

    async def usable_models(self, principal: Principal) -> dict[str, list[DataClass]]:
        res, _ = await self._resolve(principal)
        return res.usable_models()

    async def visible_names(self, principal: Principal) -> list[str]:
        res, _ = await self._resolve(principal)
        return res.visible_names()

    async def effective_preset(self, principal: Principal) -> Preset:
        res, _ = await self._resolve(principal)
        return res.preset()[0]

    async def effective_preset_with_source(self, principal: Principal) -> tuple[Preset, str]:
        res, _ = await self._resolve(principal)
        return res.preset()

    async def group_preset(self, group: str) -> tuple[Preset, str]:
        """Effective preset of a group itself (its policy preset, inherited parents, active group grants)."""
        idx, _ = self._index()
        groups = expand_groups([group])
        grants = await self.grants.active_for([], groups)
        member = Principal(subject=f"group:{group.strip('/')}", groups=[group.strip("/")])
        return Resolution(idx, member, grants, self._now()).preset()

    async def effective_access(self, principal: Principal) -> EffectiveAccess:
        res, version = await self._resolve(principal)
        return res.effective_access(version, await self.grants.version())

    async def check_tool(self, principal: Principal, tool_id: str) -> AccessCheck:
        res, _ = await self._resolve(principal)
        return res.check_tool(tool_id)

    # extras for the MCP proxy / OpenCode plugin (Phase 2B)

    async def check_mcp_server(self, principal: Principal, server: str) -> AccessCheck:
        res, _ = await self._resolve(principal)
        return res.check_mcp_server(server)

    async def visible_tools(self, principal: Principal) -> list[str]:
        res, _ = await self._resolve(principal)
        return res.visible_tools()

    async def grants_version(self) -> int:
        return await self.grants.version()

    def validate_grant(
        self, resource_type: GrantResourceType, resource: str, *, group_subject: str | None = None
    ) -> str | None:
        """Why a grant on this resource cannot be created (unknown resource / forbidden by an org lock), or None.

        Org locks with `except_groups` are only applied outright to group grants for a non-exempt group;
        for user grants the resolver enforces them at request time.
        """
        idx, _ = self._index()
        resource = normalise_resource(resource_type, resource)
        pairs: set[tuple[str, str]]
        if resource_type == GrantResourceType.connector:
            if resource not in idx.policy.connectors:
                return f"unknown connector '{_short(resource)}'"
            pairs = {("connector", resource)}
        elif resource_type in _MODEL_FAMILY:
            if not (
                resource in idx.models
                or resource in idx.alias_targets
                or resource in idx.routed_aliases
                or resource in idx.policy.skills
            ):
                return f"unknown {resource_type.value} '{_short(resource)}'"
            pairs = {(resource_type.value, resource)}
            for mid in (resource,) if resource in idx.models else idx.alias_targets.get(resource, ()):
                pairs |= idx.model_pairs(idx.models[mid])
        elif resource_type == GrantResourceType.tool:
            if resource not in idx.policy.tools:
                return f"unknown tool '{_short(resource)}'"
            pairs = {("tool", resource)}
            if idx.policy.tools[resource].server:
                pairs.add(("mcp_server", idx.policy.tools[resource].server or ""))
        else:
            if resource not in idx.policy.mcp_servers:
                return f"unknown MCP server '{_short(resource)}'"
            pairs = {("mcp_server", resource)}
        members = expand_groups([group_subject]) if group_subject else []
        hit = idx.lock_hit(pairs, members, skip_conditional=group_subject is None)
        if hit is not None:
            return f"org lock {hit.id} forbids {resource_type.value} '{_short(resource)}'"
        return None
