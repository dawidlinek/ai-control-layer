"""Addressing text inside payloads (shared by controls and transforms).

Field paths (also used in `Finding.field`):
    chat:         messages[i].content | messages[i].content[j].text | messages[i].name
                  | messages[i].tool_calls[k].function.name | messages[i].tool_calls[k].function.arguments
                  | tools[i].<key>[.<key>|[i]]...   (every string leaf of the tool definitions)
                  | params.<key>[.<key>|[i]]...     (every string leaf of the forwarded sampling params)
    completion:   content | reasoning | tool_calls[k].function.arguments
    tool_call:    arguments.<key>[.<key>|[i]]...      (every string leaf)
    tool_result:  content
    embeddings:   inputs[i]
    mcp:          tools[i].description | params.<key>...  (every string leaf)

Offsets in findings are character offsets into the text at that path *as given to the control*.
If a normaliser rewrites text, it publishes the normalised payload in `Verdict.outputs["payload"]`
and later controls inspect (and report offsets against) that payload; transforms apply to it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from acl.contracts.decision import Finding
from acl.contracts.inspection import Payload

_TOKEN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]")


def parse_path(field: str) -> list[str | int]:
    parts: list[str | int] = []
    for name, idx in _TOKEN.findall(field):
        parts.append(name if name else int(idx))
    return parts


def _leaves(obj: Any, prefix: str) -> Iterable[tuple[str, str]]:
    if isinstance(obj, str):
        yield prefix, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, f"{prefix}[{i}]")


def iter_texts(payload: Payload) -> list[tuple[str, str]]:
    """All inspectable (field, text) pairs of a payload, in a stable order."""
    out: list[tuple[str, str]] = []
    kind = payload.kind
    if kind == "chat":
        # Everything forwarded upstream that can carry free text is inspected (CP1: tool definitions,
        # message names and sampling params used to bypass every control).
        for i, m in enumerate(payload.messages):
            if isinstance(m.content, str):
                out.append((f"messages[{i}].content", m.content))
            elif isinstance(m.content, list):
                for j, part in enumerate(m.content):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        out.append((f"messages[{i}].content[{j}].text", part["text"]))
            if isinstance(m.name, str) and m.name:
                out.append((f"messages[{i}].name", m.name))
            for k, tc in enumerate(m.tool_calls or []):
                if tc.function.name:
                    out.append((f"messages[{i}].tool_calls[{k}].function.name", tc.function.name))
                out.append((f"messages[{i}].tool_calls[{k}].function.arguments", tc.function.arguments))
        for i, tool in enumerate(payload.tools or []):
            out.extend(_leaves(tool, f"tools[{i}]"))
        out.extend(_leaves(payload.params, "params"))
    elif kind == "completion":
        if payload.content:
            out.append(("content", payload.content))
        if payload.reasoning:
            out.append(("reasoning", payload.reasoning))
        for k, tc in enumerate(payload.tool_calls):
            out.append((f"tool_calls[{k}].function.arguments", tc.function.arguments))
    elif kind == "tool_call":
        out.extend(_leaves(payload.arguments, "arguments"))
    elif kind == "tool_result":
        out.append(("content", payload.content))
    elif kind == "embeddings":
        out.extend((f"inputs[{i}]", t) for i, t in enumerate(payload.inputs))
    elif kind == "mcp":
        for i, t in enumerate(payload.tools):
            if t.description:
                out.append((f"tools[{i}].description", t.description))
        out.extend(_leaves(payload.params, "params"))
    return out


def get_at(data: Any, path: list[str | int]) -> Any:
    for p in path:
        data = data[p]
    return data


def set_at(data: Any, path: list[str | int], value: Any) -> None:
    for p in path[:-1]:
        data = data[p]
    data[path[-1]] = value


def apply_replacements(payload: Payload, findings: Iterable[Finding]) -> tuple[Payload, list[Finding]]:
    """Return a new payload with each finding's span replaced by `finding.replacement`.

    Findings without replacement/offsets are ignored. Overlapping spans: the earliest-starting
    (then longest) wins; skipped findings are returned so callers can escalate (e.g. block).
    """
    by_field: dict[str, list[Finding]] = {}
    for f in findings:
        if f.replacement is not None and f.start is not None and f.end is not None and f.field:
            by_field.setdefault(f.field, []).append(f)
    if not by_field:
        return payload, []
    data = payload.model_dump(mode="python")
    skipped: list[Finding] = []
    for field, items in by_field.items():
        path = parse_path(field)
        try:
            text = get_at(data, path)
        except (KeyError, IndexError, TypeError):
            skipped.extend(items)
            continue
        if not isinstance(text, str):
            skipped.extend(items)
            continue
        chosen: list[Finding] = []
        last_end = -1
        for f in sorted(items, key=lambda f: (f.start, -(f.end or 0))):
            if f.start >= last_end and f.end <= len(text):  # type: ignore[operator]
                chosen.append(f)
                last_end = f.end  # type: ignore[assignment]
            else:
                skipped.append(f)
        for f in sorted(chosen, key=lambda f: f.start, reverse=True):  # type: ignore[arg-type,return-value]
            text = text[: f.start] + (f.replacement or "") + text[f.end :]
        set_at(data, path, text)
    return type(payload).model_validate(data), skipped
