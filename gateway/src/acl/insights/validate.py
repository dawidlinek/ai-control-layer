"""Deterministic validation of a draft skill: the LLM proposes, code decides.

Checks, per target group: shape (pydantic), skill id free, template placeholders ↔ input schema properties,
a valid object JSON Schema with `additionalProperties: false`, the model exists, has chat capability and is usable
by the group for the task's data class, the skill's data classes are covered by that model for the group, the
preset is not looser than the group's, and the tools are a subset of the group's tools.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import ValidationError

from acl.contracts.admin import InsightSkillDraft
from acl.contracts.common import DataClass, Preset
from acl.identity.access import preset_rank
from acl.insights.skills import placeholders
from acl.policy.models import Policy

SCALAR_TYPES = {"string", "number", "integer", "boolean"}
MAX_INPUTS = 10


def group_preset(policy: Policy, group: str) -> Preset:
    gp = policy.groups.get(group)
    return gp.preset if gp is not None and gp.preset is not None else policy.global_.default_preset


def resolve_model(policy: Policy, ref: str) -> str | None:
    """Concrete model id for a model id or a model alias (`fixed` aliases too); None otherwise."""
    models = policy.model_by_id()
    if ref in models:
        return ref
    for m in policy.models:
        if ref in m.aliases:
            return m.id
    alias = policy.aliases.get(ref)
    if alias is not None and alias.strategy == "fixed":
        return alias.target
    return None


def _schema_errors(schema: Any, names: list[str]) -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict):
        return ["input_schema must be a JSON object"]
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return [f"input_schema is not a valid JSON Schema: {exc.message[:200]}"]
    if schema.get("type") != "object":
        errors.append("input_schema.type must be 'object'")
    props = schema.get("properties")
    if not isinstance(props, dict) or not props:
        return [*errors, "input_schema.properties must declare the template inputs"]
    if len(props) > MAX_INPUTS:
        errors.append(f"input_schema declares more than {MAX_INPUTS} inputs")
    if schema.get("additionalProperties") is not False:
        errors.append("input_schema.additionalProperties must be false")
    for key, spec in props.items():
        if not isinstance(spec, dict) or spec.get("type") not in SCALAR_TYPES:
            errors.append(f"input {key!r} must have a scalar type (string, number, integer, boolean)")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(r not in props for r in required):
        errors.append("input_schema.required lists an undeclared input")
    declared, used = set(props), set(names)
    if used - declared:
        errors.append(f"template placeholders without an input: {', '.join(sorted(used - declared))}")
    if declared - used:
        errors.append(f"inputs never used in the template: {', '.join(sorted(declared - used))}")
    return errors


def validate_draft(
    draft: dict[str, Any] | InsightSkillDraft,
    *,
    policy: Policy,
    groups: dict[str, dict[str, list[DataClass]]],
    data_class: DataClass,
    allow_existing: bool = False,
) -> tuple[InsightSkillDraft | None, list[str]]:
    """(validated draft, []) or (None | partially valid draft, errors). `groups`: group → usable models."""
    try:
        d = draft if isinstance(draft, InsightSkillDraft) else InsightSkillDraft.model_validate(draft)
    except ValidationError as exc:
        return None, [f"{'.'.join(str(p) for p in e['loc']) or 'draft'}: {e['msg']}" for e in exc.errors()[:10]]
    errors: list[str] = []
    if d.skill_id in policy.skills and not allow_existing:
        errors.append(f"{d.skill_id} already exists")
    if d.skill_id in policy.resolvable_names() - set(policy.skills):
        errors.append(f"{d.skill_id} collides with a model or alias name")
    try:
        names = placeholders(d.template)
    except ValueError as exc:
        names = []
        errors.append(str(exc))
    if not names:
        errors.append("template needs at least one {placeholder}")
    errors += _schema_errors(d.input_schema, names)

    model_id = resolve_model(policy, d.model)
    model = policy.model_by_id().get(model_id or "")
    if model is None:
        errors.append(f"model {d.model!r} does not exist")
    elif "chat" not in model.capabilities:
        errors.append(f"model {d.model!r} cannot chat")
    if data_class not in d.data_classes:
        errors.append(f"data_classes must include the task's data class ({data_class.value})")
    if not groups:
        errors.append("no target group")
    for group, usable in groups.items():
        gp = policy.groups.get(group)
        if gp is None:
            errors.append(f"unknown group {group!r}")
            continue
        if model is not None:
            classes = usable.get(model.id)
            if classes is None:
                errors.append(f"model {d.model!r} is not available to {group}")
            else:
                missing = [c.value for c in d.data_classes if c not in classes]
                if missing:
                    errors.append(f"{group} may not send {', '.join(missing)} data to {d.model}")
        floor = group_preset(policy, group)
        if preset_rank(d.preset) < preset_rank(floor):
            errors.append(f"preset {d.preset.value} is looser than {group}'s {floor.value}")
        extra = [t for t in d.tools if t not in gp.tools]
        if extra:
            errors.append(f"tools not granted to {group}: {', '.join(sorted(extra))}")
    unknown = [t for t in d.tools if t not in policy.tools]
    if unknown:
        errors.append(f"unknown tools: {', '.join(sorted(unknown))}")
    return d, errors
