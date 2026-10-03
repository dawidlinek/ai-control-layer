"""Request-flow transforms: which findings are enforced, response hygiene, pseudonym restoration.

Restoration rules (concept §6.3): placeholders are restored ONLY into assistant text content, never
into `tool_calls` arguments, and only for allow-listed entity types. The allow-list comes from the
policy: any control's `params.restore_entity_types` (union), default `PERSON`, `EMAIL`.
"""

from __future__ import annotations

import inspect
import re
from typing import Any

from acl.contracts.common import Action
from acl.contracts.decision import Decision, Finding, Verdict
from acl.contracts.inspection import Payload
from acl.engine.engine import Engine
from acl.engine.text import get_at, iter_texts, parse_path
from acl.policy.models import Policy

TRANSFORM_ACTIONS = frozenset({Action.redact, Action.pseudonymise, Action.sanitize})
DEFAULT_RESTORE_TYPES = frozenset({"PERSON", "EMAIL"})
REASONING_KEYS = ("reasoning_content", "reasoning", "reasoning_details")
# Generic pseudonym shape produced by the vault (`<PERSON_1>`); exact placeholders come from the vault itself.
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")
PARTIAL_PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_]*$")


def non_shadow_verdicts(engine: Engine, decision: Decision) -> list[Verdict]:
    shadow = {c.id for c in engine.pipeline.controls if c.shadow}
    return [v for v in decision.verdicts if v.control_id not in shadow]


def enforced_verdicts(engine: Engine, decision: Decision) -> list[Verdict]:
    """Verdicts that actually bind: none in monitor mode, none from shadow (mode: monitor) controls."""
    return [] if decision.action == Action.monitor else non_shadow_verdicts(engine, decision)


def transform_findings(engine: Engine, decision: Decision) -> list[Finding]:
    """Findings (with replacements) of enforced redact / pseudonymise / sanitize verdicts."""
    return [
        f
        for v in enforced_verdicts(engine, decision)
        if v.action in TRANSFORM_ACTIONS
        for f in v.findings
        if f.replacement is not None
    ]


def unaddressable_fields(payload: Payload) -> set[str]:
    """Inspected fields whose path does not address exactly their own text in `payload.model_dump()`.

    Free-form JSON (tool schemas, params) may use keys such as `$ref`, `my-key` or `a.b` that
    `parse_path` cannot express; such a field may resolve to nothing or, worse, to ANOTHER leaf. A
    replacement aimed at it would then miss the real value, which would be forwarded raw. Callers must
    fail closed when an enforced transform targets one of these fields.
    """
    data = payload.model_dump(mode="python")
    owners: dict[tuple[str | int, ...], list[str]] = {}
    bad: set[str] = set()
    for field, text in iter_texts(payload):
        path = tuple(parse_path(field))
        owners.setdefault(path, []).append(field)
        try:
            ok = get_at(data, list(path)) == text
        except (KeyError, IndexError, TypeError):
            ok = False
        if not ok:
            bad.add(field)
    for fields in owners.values():
        if len(fields) > 1:
            bad.update(fields)
    return bad


def obliges_local(engine: Engine, decision: Decision) -> bool:
    """`route_local` / `downgrade` obligations: the request must be served by a local model."""
    return any(v.action in (Action.route_local, Action.downgrade) for v in enforced_verdicts(engine, decision))


def restore_entity_types(policy: Policy) -> set[str]:
    found: set[str] = set()
    for c in policy.controls:
        types = c.params.get("restore_entity_types")
        if isinstance(types, list):
            found.update(str(t) for t in types)
    return found or set(DEFAULT_RESTORE_TYPES)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def vault_placeholders(vault: Any, session_id: str) -> set[str]:
    if vault is None:
        return set()
    try:
        return set(await _maybe_await(vault.placeholders(session_id)) or ())
    except Exception:
        return set()


async def restore_text(vault: Any, session_id: str, text: str, allowed: set[str]) -> str:
    """Restore allow-listed pseudonyms in assistant text. Failure → keep the placeholders (never leak)."""
    if vault is None or not text:
        return text
    try:
        return await _maybe_await(vault.restore(session_id, text, allowed_entity_types=allowed))
    except Exception:
        return text


def strip_response_hygiene(body: dict[str, Any]) -> dict[str, Any]:
    """Remove `logprobs` and reasoning traces from an OpenAI response / chunk (in place, returned)."""
    for choice in body.get("choices") or []:
        choice.pop("logprobs", None)
        for holder in (choice.get("message"), choice.get("delta")):
            if isinstance(holder, dict):
                for key in REASONING_KEYS:
                    holder.pop(key, None)
    return body


def message_reasoning(message: dict[str, Any]) -> str | None:
    for key in REASONING_KEYS[:2]:
        val = message.get(key)
        if isinstance(val, str) and val:
            return val
    return None
