"""Org locks: what a policy edit from the panel may not do (concept §11, §7.1).

A control is locked when it has `locked: true` or is listed by a `control_locked` org lock. Compared to the
policy currently in force, a panel candidate must keep:

- every locked control present and **identical** apart from `description` (enabling a disabled locked control
  and adding `locked: true` are the only other changes allowed: both make it stricter);
- every `org_locks` entry present and identical (new locks may be added);
- `global.mode` out of `monitor` unless it already was, and `never_block` off on every preset that did not
  already have it (both switch enforcement off; they must be done in the files).

The panel (PUT / patch / rollback / validate / dry-run) enforces this with a 422. Edits made directly on disk
are not blocked (judges may edit files), but locked-control and org-lock differences are reported in the
`policy_change` event as `locked_control_modified` / `org_lock_modified`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from acl.contracts.common import PolicyMode
from acl.policy.models import ControlConfig, Policy

_UNORDERED = frozenset({"stages", "presets"})
"""List fields where only membership matters."""


@dataclass(frozen=True)
class LockViolation:
    control_id: str
    changes: tuple[str, ...]  # removed | disabled | unlocked | <field name>, e.g. action, params, mode

    def as_dict(self) -> dict[str, object]:
        return {"control_id": self.control_id, "changes": list(self.changes)}

    def __str__(self) -> str:
        return f"{self.control_id}: {', '.join(self.changes)}"


@dataclass(frozen=True)
class OrgLockViolation:
    lock_id: str
    changes: tuple[str, ...]  # removed | <field name>, e.g. allowed_tiers, controls, kind

    def as_dict(self) -> dict[str, object]:
        return {"lock_id": self.lock_id, "changes": list(self.changes)}

    def __str__(self) -> str:
        return f"org lock {self.lock_id}: {', '.join(self.changes)}"


@dataclass(frozen=True)
class PanelRestriction:
    """A setting that switches enforcement off: allowed in the files, never from the panel."""

    path: str  # global.mode | presets.<name>.never_block
    message: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "message": self.message}

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class LockReport:
    controls: list[LockViolation] = field(default_factory=list)
    org_locks: list[OrgLockViolation] = field(default_factory=list)
    restricted: list[PanelRestriction] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.controls or self.org_locks or self.restricted)


def _controls(policy: Policy) -> dict[str, ControlConfig]:
    return {c.id: c for c in policy.controls}


def _norm(name: str, value: Any) -> Any:
    if name in _UNORDERED and isinstance(value, list):
        return sorted(map(str, value))
    return value


def _control_changes(before: ControlConfig, after: ControlConfig) -> list[str]:
    b = before.model_dump(mode="json")
    a = after.model_dump(mode="json")
    changes: list[str] = []
    for name in ControlConfig.model_fields:
        if name in ("id", "description"):
            continue
        old, new = _norm(name, b.get(name)), _norm(name, a.get(name))
        if old == new:
            continue
        if name == "enabled":
            if old and not new:
                changes.append("disabled")  # enabling a disabled locked control is a tightening: allowed
        elif name == "locked":
            if old and not new:
                changes.append("unlocked")  # adding `locked: true` is allowed
        else:
            changes.append(name)
    return changes


def locked_violations(old: Policy, new: Policy) -> list[LockViolation]:
    """Locked controls (in `old`) that `new` removes, unlocks or changes in anything but `description`."""
    old_controls, new_controls = _controls(old), _controls(new)
    new_locked = new.locked_control_ids()
    out: list[LockViolation] = []
    for cid in sorted(old.locked_control_ids()):
        before = old_controls.get(cid)
        after = new_controls.get(cid)
        changes: list[str] = []
        if after is None:
            changes.append("removed")
        else:
            if before is not None:
                changes.extend(_control_changes(before, after))
            if cid not in new_locked and "unlocked" not in changes:
                changes.append("unlocked")  # dropped from a control_locked org lock
        if changes:
            out.append(LockViolation(cid, tuple(changes)))
    return out


def org_lock_violations(old: Policy, new: Policy) -> list[OrgLockViolation]:
    """Org locks (in `old`) that `new` removes or changes in any field. Adding locks is fine."""
    new_locks = {lock.id: lock for lock in new.org_locks}
    out: list[OrgLockViolation] = []
    for lock in old.org_locks:
        after = new_locks.get(lock.id)
        if after is None:
            out.append(OrgLockViolation(lock.id, ("removed",)))
            continue
        b, a = lock.model_dump(mode="json"), after.model_dump(mode="json")
        changes = tuple(k for k in sorted(set(b) | set(a)) if k != "id" and b.get(k) != a.get(k))
        if changes:
            out.append(OrgLockViolation(lock.id, changes))
    return out


def panel_restrictions(old: Policy, new: Policy) -> list[PanelRestriction]:
    """Settings that turn enforcement off and may only be changed in the files."""
    out: list[PanelRestriction] = []
    if new.global_.mode == PolicyMode.monitor and old.global_.mode != PolicyMode.monitor:
        out.append(
            PanelRestriction(
                "global.mode",
                "switching the whole gateway to monitor mode cannot be done from the panel; edit the policy files",
            )
        )
    for name, preset in sorted(new.presets.items()):
        before = old.presets.get(name)
        if preset.never_block and not (before is not None and before.never_block):
            out.append(
                PanelRestriction(
                    f"presets.{name}.never_block",
                    "making a preset never block cannot be done from the panel; edit the policy files",
                )
            )
    return out


def lock_report(old: Policy, new: Policy, *, panel: bool) -> LockReport:
    """Everything `new` changes about the locks of `old`; `panel=True` adds the panel-only restrictions."""
    return LockReport(
        controls=locked_violations(old, new),
        org_locks=org_lock_violations(old, new),
        restricted=panel_restrictions(old, new) if panel else [],
    )
