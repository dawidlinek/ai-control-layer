"""Text slots of a case input: where an attack variant may change the text, and what kind of text it is.

A *slot* is one string inside a case's `input` (the whole string for a shorthand input, a chat message's `content`,
a tool result's `content`, one string argument of a tool call). Variants change exactly one slot at a time.

Only slots with a role the techniques understand are extracted (see `techniques.ROLE_TECHNIQUES`). Structural
arguments (recipient lists, patch bodies, numbers, nested non-text values) are left alone: obfuscating a recipient
address is not an attack variant of "send mail to an outside domain", it is a different (invalid) call.

Skipped on purpose (reported by the runner with these reasons):
    non_text_payload             mcp_* / artifact points: detection depends on descriptors, URLs and metadata, not text
    monitor_case                 the case is a monitor-preset / monitor-mode duplicate of another case
    format_property              SEC-HYG-01 cases about think-blocks / reasoning / logprobs: a response-format property,
                                 not hidden content, so obfuscating it is not an attack
    no_text_slot                 no extractable string (malformed values, numbers)
    baseline_not_intervened      the original attack is not intervened on at balanced/strict/paranoid either
    independent_of_text          the system intervenes even when every text slot is replaced by a neutral filler
                                 (tool tier, group, session labels, budgets ...): the variants could not test anything
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

COMMAND_KEYS = frozenset(["command", "cmd", "script", "shell", "bash", "commandline", "command_line"])
URL_KEYS = frozenset(["url", "uri", "endpoint", "href", "link", "webhook", "base_url", "location"])
PATH_KEYS = frozenset(["path", "filepath", "file", "filename", "directory", "dir", "target", "destination"])
SQL_KEYS = frozenset(["sql", "statement", "query"])
CODE_KEYS = frozenset(["code"])
STRUCTURAL_KEYS = frozenset(
    ["to", "cc", "bcc", "recipient", "recipients", "email", "emails", "mailto", "patchtext", "patch", "diff", "cwd",
     "method", "host", "hostname", "server", "domain", "workspace_root", "packages", "package", "dependencies"]
)  # fmt: skip

# What a slot is replaced with to ask "does the system still intervene without this text?".
NEUTRAL = {
    "prose": "hello",
    "command": "echo ok",
    "pycode": "print(1)",
    "url": "https://example.org/",
    "path": "notes.txt",
    "sql": "SELECT 1",
}

SKIP_POINTS = {"mcp_initialize", "mcp_tools_list", "mcp_tool_call", "mcp_sampling", "mcp_elicitation", "artifact_load"}


@dataclass(frozen=True)
class Slot:
    path: tuple[str | int, ...]
    role: str
    value: str

    @property
    def key(self) -> str:
        return ".".join(str(p) for p in self.path) or "input"


def _role_for_key(key: str) -> str | None:
    k = key.lower()
    if k in STRUCTURAL_KEYS:
        return None
    if k in COMMAND_KEYS:
        return "command"
    if k in URL_KEYS:
        return "url"
    if k in PATH_KEYS:
        return "path"
    if k in SQL_KEYS:
        return "sql"
    if k in CODE_KEYS:
        return "pycode"
    return "prose"


def _walk_args(value: Any, path: tuple[str | int, ...], role: str | None, out: list[Slot]) -> None:
    if isinstance(value, str):
        if role and value.strip():
            out.append(Slot(path, role, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            _walk_args(v, (*path, k), _role_for_key(str(k)), out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _walk_args(v, (*path, i), role if role == "prose" else None, out)


def extract_slots(data: Any) -> list[Slot]:
    """The text slots of a case `input` (str, chat dict, tool call / tool result dict, completion dict)."""
    if isinstance(data, str):
        return [Slot((), "prose", data)] if data.strip() else []
    if not isinstance(data, dict) or data.get("kind") in ("mcp", "artifact"):
        return []
    out: list[Slot] = []
    if isinstance(data.get("messages"), list):
        for i, m in enumerate(data["messages"]):
            if isinstance(m, dict) and isinstance(m.get("content"), str) and m["content"].strip():
                out.append(Slot(("messages", i, "content"), "prose", m["content"]))
        return out
    if "tool" in data and isinstance(data.get("arguments"), dict):
        _walk_args(data["arguments"], ("arguments",), None, out)
        return out
    if "tool" in data and isinstance(data.get("content"), str):
        return [Slot(("content",), "prose", data["content"])]
    if isinstance(data.get("content"), str):  # completion dict without reasoning / logprobs fields
        return [Slot(("content",), "prose", data["content"])]
    return out


def _set(data: Any, path: tuple[str | int, ...], value: str) -> Any:
    if not path:
        return value
    out = copy.deepcopy(data)
    node = out
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = value
    return out


def replace_slot(data: Any, slot: Slot, text: str) -> Any:
    """A deep copy of `data` with `slot` set to `text`."""
    return _set(data, slot.path, text)


def neutralise(data: Any, slot: Slot) -> Any:
    return replace_slot(data, slot, NEUTRAL[slot.role])


def apply_messages(data: Any, slot: Slot, parts: list[str], *, point: str) -> Any | None:
    """Split the slot text across consecutive chat messages (ingress only). None when that is not possible."""
    if point != "ingress":
        return None
    if not slot.path:
        return {"messages": [{"role": "user", "content": p} for p in parts]}
    if slot.path[0] == "messages" and isinstance(data, dict):
        out = copy.deepcopy(data)
        i = slot.path[1]
        assert isinstance(i, int)
        base = out["messages"][i]
        out["messages"][i : i + 1] = [{**base, "content": p} for p in parts]
        return out
    return None
