"""Skill templates: placeholder grammar, input extraction and server-side rendering of `skill/<name>` requests.

A request to a skill is rewritten before inspection: the client's messages are replaced by the skill's template
rendered with the inputs (the last user message, either a JSON object of inputs or — for a one-input skill — the
plain text), validated against the skill's input schema. The client cannot change the prompt, the model, the
tools (narrowed to the skill's list) or loosen the preset (the stricter of the caller's and the skill's applies).
"""

from __future__ import annotations

import json
import re
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from acl.contracts.common import Preset
from acl.contracts.inspection import ChatMessage, ChatPayload
from acl.identity.access import preset_rank
from acl.policy.models import SkillConfig

PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
NAME = re.compile(r"^[a-z_][a-z0-9_]{0,39}$")
MAX_INPUT_CHARS = 50_000


class SkillInputError(ValueError):
    """The request's inputs do not fit the skill (message is safe to return: no input values)."""


def placeholders(template: str) -> list[str]:
    """Placeholder names in order of first use. Raises ValueError on a malformed placeholder or stray brace."""
    names: list[str] = []
    for raw in PLACEHOLDER.findall(template):
        if not NAME.match(raw):
            raise ValueError(f"placeholder {{{raw[:40]}}} must be a lower-case name like {{application}}")
        if raw not in names:
            names.append(raw)
    rest = PLACEHOLDER.sub("", template)
    if "{" in rest or "}" in rest:
        raise ValueError("template has an unmatched '{' or '}'")
    return names


def render(template: str, inputs: dict[str, Any]) -> str:
    """Substitute `{name}` with the input (no format-spec / attribute access: plain names only)."""

    def sub(m: re.Match[str]) -> str:
        v = inputs.get(m.group(1), "")
        return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)

    return PLACEHOLDER.sub(sub, template)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return ""


def string_properties(schema: dict[str, Any]) -> list[str]:
    props = schema.get("properties") or {}
    return [k for k, v in props.items() if isinstance(v, dict) and v.get("type", "string") == "string"]


def skill_inputs(skill: SkillConfig, messages: list[ChatMessage]) -> dict[str, Any]:
    """Inputs from the last user message: a JSON object, or the whole text for a skill with one text input."""
    last = next((m for m in reversed(messages) if m.role == "user"), None)
    text = _text(last.content).strip() if last is not None else ""
    if not text:
        raise SkillInputError("a skill request needs a user message with the inputs")
    if len(text) > MAX_INPUT_CHARS:
        raise SkillInputError(f"skill inputs are longer than {MAX_INPUT_CHARS} characters")
    schema = skill.input_schema or {}
    props = list((schema.get("properties") or {}).keys())
    inputs: dict[str, Any] | None = None
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and (set(parsed) & set(props) or len(props) != 1):
            inputs = parsed
    if inputs is None:
        strings = string_properties(schema)
        if len(props) == 1 and strings == props:
            inputs = {props[0]: text}
        else:
            raise SkillInputError(f"send the inputs as a JSON object with: {', '.join(props) or 'no fields'}")
    try:
        errors = sorted(Draft202012Validator(schema).iter_errors(inputs), key=lambda e: list(e.path))
    except SchemaError as exc:  # pragma: no cover - policy validation keeps schemas valid
        raise SkillInputError("the skill's input schema is invalid") from exc
    if errors:
        e = errors[0]
        where = "/".join(str(p) for p in e.path) or "inputs"
        raise SkillInputError(f"invalid skill input at {where}: {e.validator} constraint failed")
    return inputs


def _tool_names(tool_id: str) -> set[str]:
    server, _, name = tool_id.partition(".")
    return {tool_id, tool_id.replace(".", "_"), name, f"{server}__{name}"}


def skill_payload(skill: SkillConfig, payload: ChatPayload) -> ChatPayload:
    """The payload actually inspected and sent: rendered template only; tools narrowed to the skill's tools."""
    inputs = skill_inputs(skill, payload.messages)
    prompt = render(skill.template, inputs)
    tools = None
    if payload.tools and skill.tools:
        allowed = set().union(*(_tool_names(t) for t in skill.tools))
        kept = [t for t in payload.tools if str((t.get("function") or {}).get("name", "")) in allowed]
        tools = kept or None
    return ChatPayload(messages=[ChatMessage(role="user", content=prompt)], tools=tools, params=dict(payload.params))


def skill_preset(current: Preset, skill: SkillConfig) -> Preset:
    """A skill can only make the preset stricter."""
    return skill.preset if preset_rank(skill.preset) > preset_rank(current) else current
