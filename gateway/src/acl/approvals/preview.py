"""Redacted previews of held tool calls (shown to approvers; concept §9 "Approvals").

Only the fields an approver needs are shown (command, path, url, recipients, sql); everything else appears as
`key=<n chars>`. Secret-looking spans are masked with `find_secrets` and long values are truncated. Previews are
stored and returned by the admin API, so they must never carry raw credentials.
"""

from __future__ import annotations

from typing import Any

from acl.contracts.inspection import ToolCallPayload
from acl.controls.secrets.rules import find_secrets

_SHOWN = frozenset(
    {
        "command",
        "cmd",
        "path",
        "filepath",
        "file_path",
        "url",
        "uri",
        "to",
        "cc",
        "bcc",
        "recipient",
        "recipients",
        "subject",
        "sql",
        "query",
        "package",
        "packages",
        "description",
        "workdir",
        "cwd",
    }
)
MAX_VALUE = 800


def _mask(text: str) -> str:
    hits = sorted(find_secrets(text), key=lambda h: h.start, reverse=True)
    for h in hits:
        text = text[: h.start] + "[REDACTED]" + text[h.end :]
    return text


def _show(value: Any) -> str:
    if isinstance(value, str):
        text = _mask(value)
    elif isinstance(value, list) and all(isinstance(v, str) for v in value):
        text = _mask(" ".join(value))
    else:
        return f"<{type(value).__name__}>"
    return text if len(text) <= MAX_VALUE else text[: MAX_VALUE - 1] + "…"


def build_preview(payload: ToolCallPayload, *, why: str = "") -> str:
    parts = [f"{payload.tool}"]
    for key, value in payload.arguments.items():
        if key.lower() in _SHOWN:
            parts.append(f"{key}: {_show(value)}")
        elif isinstance(value, str):
            parts.append(f"{key}=<{len(value)} chars>")
        else:
            parts.append(f"{key}=<{type(value).__name__}>")
    text = "\n".join(parts)
    if why:
        text += f"\nwhy: {why}"
    return text[:2000]
