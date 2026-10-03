"""Org locks: what a policy edit may not do to locked controls (concept §11, §7.1).

A control is locked when it has `locked: true` or is listed by a `control_locked` org lock. Compared to the
policy currently in force, a candidate policy must keep every locked control present, enabled (if it was),
with the same `action` and `stages`, and still locked.

The panel (PUT / rollback) enforces this with a 422. Edits made directly on disk are not blocked (judges may
edit files), but they are reported in the `policy_change` event as `locked_control_modified`.
"""

from __future__ import annotations

from dataclasses import dataclass

from acl.policy.models import ControlConfig, Policy


@dataclass(frozen=True)
class LockViolation:
    control_id: str
    changes: tuple[str, ...]  # removed | disabled | action | stages | unlocked

    def as_dict(self) -> dict[str, object]:
        return {"control_id": self.control_id, "changes": list(self.changes)}

    def __str__(self) -> str:
        return f"{self.control_id}: {', '.join(self.changes)}"


def _controls(policy: Policy) -> dict[str, ControlConfig]:
    return {c.id: c for c in policy.controls}


def locked_violations(old: Policy, new: Policy) -> list[LockViolation]:
    """Changes in `new` that weaken a control locked in `old`."""
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
                if before.enabled and not after.enabled:
                    changes.append("disabled")
                if before.action != after.action:
                    changes.append("action")
                if set(before.stages) != set(after.stages):
                    changes.append("stages")
                if before.locked and not after.locked:
                    changes.append("unlocked")
            if cid not in new_locked and "unlocked" not in changes:
                changes.append("unlocked")  # dropped from a control_locked org lock
        if changes:
            out.append(LockViolation(cid, tuple(changes)))
    return out
