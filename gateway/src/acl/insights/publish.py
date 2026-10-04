"""Publish a validated skill through the policy service writer (concept §11.1): ONE new policy version that adds
`skills.<id>` and lists the skill under each target group's `skills:`. Same path as panel edits: optimistic
compile of the whole candidate set, org-lock check, atomic write, hot swap, version snapshot, `policy_change` event.
"""

from __future__ import annotations

import io
from typing import Any

from ruamel.yaml import YAML

from acl.contracts.admin import InsightSkillDraft
from acl.contracts.inspection import Principal
from acl.insights.embed import InsightsError
from acl.policy.yamledit import PathOp


def skill_body(d: InsightSkillDraft) -> dict[str, Any]:
    """The `skills.<id>` entry as written to the policy file (SkillConfig fields only)."""
    return {
        "description": d.description,
        "template": d.template,
        "input_schema": d.input_schema,
        "model": d.model,
        "tools": list(d.tools),
        "preset": d.preset.value,
        "data_classes": [c.value for c in d.data_classes],
    }


def _top_level(text: str) -> dict[str, Any]:
    doc = YAML(typ="safe").load(io.StringIO(text))
    return doc if isinstance(doc, dict) else {}


def plan_edits(files: dict[str, str], d: InsightSkillDraft, groups: list[str]) -> dict[str, list[PathOp]]:
    """Which file gets which structured edit (sections may live in any file; each section in only one)."""
    docs = {name: _top_level(text) for name, text in sorted(files.items())}
    skills_file = next((n for n, doc in docs.items() if "skills" in doc), None)
    skills_file = skills_file or next((n for n, doc in docs.items() if "models" in doc), None)
    groups_file = next((n for n, doc in docs.items() if "groups" in doc), None)
    if skills_file is None or groups_file is None:
        raise InsightsError("cannot find the policy files holding skills and groups")
    edits: dict[str, list[PathOp]] = {}
    body = skill_body(d)
    if docs[skills_file].get("skills"):
        edits.setdefault(skills_file, []).append(PathOp("set", ["skills", d.skill_id], body))
    else:
        edits.setdefault(skills_file, []).append(PathOp("set", ["skills"], {d.skill_id: body}))
    group_docs = docs[groups_file].get("groups") or {}
    for g in groups:
        current = list((group_docs.get(g) or {}).get("skills") or [])
        if d.skill_id not in current:
            edits.setdefault(groups_file, []).append(PathOp("set", ["groups", g, "skills"], [*current, d.skill_id]))
    return edits


async def publish_skill(
    app: Any, d: InsightSkillDraft, groups: list[str], principal: Principal | None, message: str
) -> tuple[str, int | None]:
    """Write the skill; returns (policy version, version number). Policy errors propagate as the writer's errors."""
    writer = getattr(app.state, "policy_writer", None)
    service = getattr(app.state, "policy_service", None)
    if writer is None or service is None:
        raise InsightsError("the policy writer is not available")
    files = {n: f.content for n, f in service.current_files().items()}
    status = await writer.patch_files(plan_edits(files, d, groups), principal, message=message)
    version_id = None
    if service.versions is not None:
        latest = await service.versions.latest()
        if latest is not None and latest.version == status.version:
            version_id = latest.id
    return status.version, version_id
