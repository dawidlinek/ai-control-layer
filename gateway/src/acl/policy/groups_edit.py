"""Panel-editable group settings <-> policy YAML (HANDOFF §5.5 Groups tab).

`read_settings` derives `GroupSettings` from a loaded `Policy`; `plan_edit` turns a desired `GroupSettings` into
structured `PathOp`s per file (`groups.yaml`, `budgets.yaml`) plus human-readable change lines. Applying the ops
and validating the candidate (cross references, org locks) is the job of `PolicyWriter` / `PolicyService`; nothing
here bypasses them.
"""

from __future__ import annotations

import difflib
import io
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ruamel.yaml.error import YAMLError
from sqlalchemy import case, func, select

from acl.audit.db_models import AuditEventRow
from acl.audit.incidents import as_utc
from acl.contracts.admin import (
    DryRunRequest,
    Group,
    GroupSettings,
    GroupSettingsPreview,
    PolicyError,
    UsageStats,
)
from acl.contracts.audit import EventType
from acl.contracts.common import ConnectorTier, DataClass, ToolTier
from acl.identity.access import PolicyIndex
from acl.policy.errors import FileNotFound, LockedControl, ValidationFailed
from acl.policy.models import Policy
from acl.policy.yamledit import PathOp, rt_yaml

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from acl.policy.service import PolicyService
    from acl.policy.writer import PolicyWriter

log = logging.getLogger(__name__)

GROUPS_FILE = "groups.yaml"
BUDGETS_FILE = "budgets.yaml"

_CEILING_ORDER = {DataClass.public: 0, DataClass.internal: 1}


class GroupSettingsInvalid(ValueError):
    """The requested settings are inconsistent on their own (before the policy compiler sees them)."""

    def __init__(self, errors: list[PolicyError]) -> None:
        super().__init__("; ".join(e.message for e in errors))
        self.errors = errors


@dataclass
class GroupEditPlan:
    group: str
    changes: list[str] = field(default_factory=list)
    edits: dict[str, list[PathOp]] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.edits


# ---------------------------------------------------------------- read


def cloud_model_refs(policy: Policy, refs: Sequence[str]) -> list[str]:
    """The entries of `refs` that resolve to at least one cloud-tier model (ids, aliases, fixed aliases,
    `connector:<id>`). Routed aliases (`auto`) count when a routing target is a cloud model: `auto` sends public /
    internal data to the cloud, so a group holding it does not have "no cloud". Skills do not count."""
    idx = PolicyIndex(policy)
    out: list[str] = []
    for ref in refs:
        if ref in policy.skills:
            continue
        if any(idx.tier(idx.models[mid]) == ConnectorTier.cloud for mid in idx.expand(ref) if mid in idx.models):
            out.append(ref)
    return out


def granted_tools(policy: Policy, group: str) -> list[str]:
    gp = policy.groups[group]
    return [tid for tid, grant in gp.tools.items() if grant.tier != ToolTier.deny]


def read_settings(policy: Policy, group: str) -> GroupSettings:
    """`GroupSettings` of policy group `group` (KeyError if it does not exist)."""
    gp = policy.groups[group]
    if cloud_model_refs(policy, gp.models):
        ceiling = gp.max_external_data_class
        cloud = "public" if ceiling == DataClass.public else "internal"  # confidential+ is clamped (LOCK-01)
    else:
        cloud = "none"
    limits = policy.budgets.groups.get(group)
    return GroupSettings(
        preset=gp.preset,
        models=list(gp.models),
        tools=granted_tools(policy, group),
        max_cloud_data_class=cloud,  # type: ignore[arg-type]
        daily_budget_usd=limits.usd_day if limits is not None else None,
    )


# ---------------------------------------------------------------- plan


def _dedupe(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _num(value: float | None) -> str:
    return "none" if value is None else f"{value:g}"


def _has_path(text: str, path: Sequence[str]) -> bool:
    try:
        node: Any = rt_yaml().load(io.StringIO(text))
    except YAMLError:
        return False
    for part in path:
        if not isinstance(node, Mapping) or part not in node:
            return False
        node = node[part]
    return True


def plan_edit(
    policy: Policy, group: str, wanted: GroupSettings, texts: Mapping[str, str] | None = None
) -> GroupEditPlan:
    """Diff `wanted` against the current settings of `group`. Raises `GroupSettingsInvalid` for contradictions.

    `texts` (current file contents, optional) lets the planner create missing `budgets` sections correctly."""
    if group not in policy.groups:
        raise KeyError(group)
    gp = policy.groups[group]
    current = read_settings(policy, group)
    plan = GroupEditPlan(group)
    groups_ops: list[PathOp] = []
    budget_ops: list[PathOp] = []
    gpath: list[Any] = ["groups", group]

    new_models = _dedupe(wanted.models)
    new_tools = _dedupe(wanted.tools)

    if wanted.max_cloud_data_class == "none":
        cloud = cloud_model_refs(policy, new_models)
        if cloud:
            raise GroupSettingsInvalid(
                [
                    PolicyError(
                        file=GROUPS_FILE,
                        path=f"groups.{group}.models",
                        message=f"remove cloud models first or allow public/internal data "
                        f"(cloud models: {', '.join(cloud)})",
                    )
                ]
            )

    # preset ---------------------------------------------------------
    if wanted.preset != current.preset:
        before = current.preset.value if current.preset else "default"
        after = wanted.preset.value if wanted.preset else "default"
        plan.changes.append(f"preset {before} → {after}")
        if wanted.preset is None:
            groups_ops.append(PathOp("delete", [*gpath, "preset"]))
        else:
            groups_ops.append(PathOp("set", [*gpath, "preset"], wanted.preset.value))

    # models ---------------------------------------------------------
    old_models = list(gp.models)
    added_models = [m for m in new_models if m not in old_models]
    removed_models = [m for m in old_models if m not in new_models]
    if added_models or removed_models:
        plan.changes += [f"+ model {m}" for m in added_models] + [f"- model {m}" for m in removed_models]
        merged = [m for m in old_models if m in new_models] + added_models
        groups_ops.append(PathOp("set", [*gpath, "models"], merged))

    # tools ----------------------------------------------------------
    old_granted = set(current.tools)
    added_tools = [t for t in new_tools if t not in old_granted]
    removed_tools = [t for t in current.tools if t not in new_tools]
    if added_tools or removed_tools:
        plan.changes += [f"+ tool {t}" for t in added_tools] + [f"- tool {t}" for t in removed_tools]
        if not gp.tools:
            groups_text = (texts or {}).get(GROUPS_FILE)
            tools_present = _has_path(groups_text, ["groups", group, "tools"]) if groups_text else False
            if added_tools and not tools_present:
                groups_ops.append(PathOp("set", [*gpath, "tools"], {t: {} for t in added_tools}))
                added_tools = []
        for t in added_tools:
            existing = gp.tools.get(t)
            if existing is None:
                groups_ops.append(PathOp("set", [*gpath, "tools", t], {}))
            else:  # listed with `tier: deny`: granting it again means dropping the deny
                groups_ops.append(PathOp("delete", [*gpath, "tools", t, "tier"]))
        for t in removed_tools:
            groups_ops.append(PathOp("delete", [*gpath, "tools", t]))

    # cloud data ceiling ----------------------------------------------
    if wanted.max_cloud_data_class != current.max_cloud_data_class:
        plan.changes.append(f"cloud data {current.max_cloud_data_class} → {wanted.max_cloud_data_class}")
        stored = "public" if wanted.max_cloud_data_class == "none" else wanted.max_cloud_data_class
        if stored != gp.max_external_data_class.value:
            groups_ops.append(PathOp("set", [*gpath, "max_external_data_class"], stored))

    # daily budget -----------------------------------------------------
    if wanted.daily_budget_usd != current.daily_budget_usd:
        plan.changes.append(
            f"daily budget {_num(current.daily_budget_usd)} → {_num(wanted.daily_budget_usd)}"
            + (" USD" if wanted.daily_budget_usd is not None else "")
        )
        budget_ops.extend(_budget_ops(policy, group, wanted.daily_budget_usd, (texts or {}).get(BUDGETS_FILE)))

    if groups_ops:
        plan.edits[GROUPS_FILE] = groups_ops
    if budget_ops:
        plan.edits[BUDGETS_FILE] = budget_ops
    return plan


def _budget_ops(policy: Policy, group: str, usd: float | None, text: str | None) -> list[PathOp]:
    limits = policy.budgets.groups.get(group)
    if usd is None:
        return (
            [PathOp("delete", ["budgets", "groups", group, "usd_day"])] if limits and limits.usd_day is not None else []
        )
    if limits is not None:
        return [PathOp("set", ["budgets", "groups", group, "usd_day"], usd)]
    if text is None or _has_path(text, ["budgets", "groups"]):
        return [PathOp("set", ["budgets", "groups", group], {"usd_day": usd})]
    return [PathOp("set", ["budgets", "groups"], {group: {"usd_day": usd}})]


# ---------------------------------------------------------------- diff


def unified_diff(before: Mapping[str, str], after: Mapping[str, str]) -> tuple[list[str], str]:
    """(changed file names, unified diff of them) between two file sets."""
    changed = sorted(n for n in after if before.get(n) != after[n])
    parts: list[str] = []
    for name in changed:
        parts.extend(
            difflib.unified_diff(
                before.get(name, "").splitlines(keepends=True),
                after[name].splitlines(keepends=True),
                fromfile=f"a/{name}",
                tofile=f"b/{name}",
            )
        )
    text = "".join(p if p.endswith("\n") else p + "\n" for p in parts)
    return changed, text


# ---------------------------------------------------------------- admin API helpers


def today_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


async def stats_today(sessions: async_sessionmaker[AsyncSession] | None) -> dict[str, UsageStats]:
    """Decision-event traffic since 00:00 UTC per group name (one grouped query over the audit index).

    The index stores a request's groups as one `|a|b|` string, so rows are aggregated per distinct group set in SQL
    and then distributed to each member group here."""
    if sessions is None:
        return {}
    row = AuditEventRow
    stmt = (
        select(
            row.groups_text,
            func.count(),
            func.coalesce(func.sum(row.input_tokens), 0),
            func.coalesce(func.sum(row.output_tokens), 0),
            func.coalesce(func.sum(case((row.action == "block", 1), else_=0)), 0),
            func.coalesce(func.sum(row.usd), 0.0),
            func.coalesce(func.sum(row.gpu_seconds), 0.0),
            func.max(row.timestamp),
        )
        .where(row.event_type == EventType.decision.value, row.timestamp >= today_start())
        .group_by(row.groups_text)
    )
    try:
        async with sessions() as s:
            rows = list((await s.execute(stmt)).all())
    except Exception:
        log.exception("could not read today's group usage from the audit index")
        return {}
    out: dict[str, UsageStats] = {}
    for groups_text, n, tin, tout, blocks, usd, gpu, last in rows:
        for g in (p for p in (groups_text or "").split("|") if p):
            st = out.setdefault(g, UsageStats(window="today"))
            st.requests += int(n)
            st.tokens_in += int(tin)
            st.tokens_out += int(tout)
            st.blocks += int(blocks)
            st.usd += float(usd)
            st.gpu_seconds += float(gpu)
            if last is not None:
                last = as_utc(last)
                if st.last_active is None or last > st.last_active:
                    st.last_active = last
    return out


def group_line(groups_text: str | None, group: str) -> int | None:
    """1-based line of the group's key in `groups.yaml` text."""
    if not groups_text:
        return None
    try:
        doc = rt_yaml().load(io.StringIO(groups_text))
        node = doc["groups"]
        return int(node.lc.key(group)[0]) + 1 if group in node else None
    except (YAMLError, KeyError, TypeError, AttributeError):
        return None


def group_model(
    name: str,
    policy: Policy | None,
    members: int,
    stats: Mapping[str, UsageStats],
    groups_text: str | None,
) -> Group:
    """The `Group` contract object for `name` (policy and/or Keycloak)."""
    gp = policy.groups.get(name) if policy is not None else None
    in_kc = members > 0
    source = "both" if gp is not None and in_kc else "policy" if gp is not None else "keycloak"
    line = group_line(groups_text, name) if gp is not None else None
    return Group(
        name=name,
        description=gp.description if gp else "",
        preset=gp.preset if gp else None,
        members=members,
        source=source,  # type: ignore[arg-type]
        settings=read_settings(policy, name) if gp is not None and policy is not None else None,
        stats_today=stats.get(name) or UsageStats(window="today"),
        policy_file=GROUPS_FILE if gp is not None else None,
        policy_line=line,
    )


def read_groups_text(service: PolicyService) -> str | None:
    try:
        return service.get_file(GROUPS_FILE).content
    except (FileNotFound, ValidationFailed):
        return None


async def preview_settings(
    service: PolicyService, writer: PolicyWriter, group: str, wanted: GroupSettings
) -> GroupSettingsPreview:
    """Draft -> validate -> diff -> impact. Never writes; validation problems come back as `valid=False`."""
    loaded = service.loaded
    if loaded is None or group not in loaded.policy.groups:
        raise FileNotFound("group")
    try:
        texts = {n: f.content for n, f in service.current_files().items()}
        plan = plan_edit(loaded.policy, group, wanted, texts)
        if plan.empty:
            return GroupSettingsPreview(valid=True, candidate_version=loaded.version)
        patched = writer.preview_patch(plan.edits)
    except GroupSettingsInvalid as exc:
        return GroupSettingsPreview(valid=False, errors=exc.errors)
    except ValidationFailed as exc:
        return GroupSettingsPreview(valid=False, errors=exc.errors)
    changed, diff = unified_diff(texts, patched)
    base = GroupSettingsPreview(valid=False, changes=plan.changes, files_changed=changed, diff=diff)
    try:
        checked = await service.validate(patched)
    except LockedControl as exc:  # validate() already maps this; defensive
        return base.model_copy(update={"errors": exc.errors()})
    if not checked.valid:
        return base.model_copy(update={"errors": checked.errors})
    impact = await service.dry_run(DryRunRequest(files=patched, last_n=500))
    return base.model_copy(update={"valid": True, "candidate_version": checked.candidate_version, "impact": impact})
