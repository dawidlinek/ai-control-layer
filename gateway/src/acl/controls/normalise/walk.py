"""Addressable text leaves of a payload (mirrors `acl.engine.text.iter_texts` field naming).

`iter_texts` yields (field, text) only; the normaliser must also *write* normalised text back, and dict
keys that are not identifiers (e.g. `my-key`) cannot be addressed through `parse_path`. So this module
yields explicit path tuples next to the field string. A unit test pins it to `iter_texts`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from acl.contracts.inspection import Payload

MAX_DEPTH = 32
MAX_LEAVES = 20_000


class TooDeep(ValueError):
    """Payload nesting/size beyond what the normaliser accepts (treated as a malformed call)."""


@dataclass(frozen=True, slots=True)
class Leaf:
    field: str
    path: tuple[str | int, ...]
    text: str
    json_args: bool = False  # a chat/completion tool_call `function.arguments` JSON string


def _leaves(obj: Any, path: tuple[str | int, ...], prefix: str, depth: int, out: list[Leaf]) -> None:
    if depth > MAX_DEPTH:
        raise TooDeep("nesting too deep")
    if isinstance(obj, str):
        out.append(Leaf(prefix, path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _leaves(v, (*path, k), f"{prefix}.{k}" if prefix else str(k), depth + 1, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _leaves(v, (*path, i), f"{prefix}[{i}]", depth + 1, out)
    if len(out) > MAX_LEAVES:
        raise TooDeep("too many string values")


def walk_leaves(payload: Payload) -> list[Leaf]:
    """All inspectable text leaves with explicit paths into `payload.model_dump()`."""
    out: list[Leaf] = []
    kind = payload.kind
    if kind == "chat":
        for i, m in enumerate(payload.messages):
            if isinstance(m.content, str):
                out.append(Leaf(f"messages[{i}].content", ("messages", i, "content"), m.content))
            elif isinstance(m.content, list):
                for j, part in enumerate(m.content):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        out.append(
                            Leaf(
                                f"messages[{i}].content[{j}].text", ("messages", i, "content", j, "text"), part["text"]
                            )
                        )
            for k, tc in enumerate(m.tool_calls or []):
                out.append(
                    Leaf(
                        f"messages[{i}].tool_calls[{k}].function.arguments",
                        ("messages", i, "tool_calls", k, "function", "arguments"),
                        tc.function.arguments,
                        True,
                    )
                )
    elif kind == "completion":
        if payload.content:
            out.append(Leaf("content", ("content",), payload.content))
        if payload.reasoning:
            out.append(Leaf("reasoning", ("reasoning",), payload.reasoning))
        for k, tc in enumerate(payload.tool_calls):
            out.append(
                Leaf(
                    f"tool_calls[{k}].function.arguments",
                    ("tool_calls", k, "function", "arguments"),
                    tc.function.arguments,
                    True,
                )
            )
    elif kind == "tool_call":
        _leaves(payload.arguments, ("arguments",), "arguments", 0, out)
    elif kind == "tool_result":
        out.append(Leaf("content", ("content",), payload.content))
    elif kind == "embeddings":
        out.extend(Leaf(f"inputs[{i}]", ("inputs", i), t) for i, t in enumerate(payload.inputs))
    elif kind == "mcp":
        for i, t in enumerate(payload.tools):
            if t.description:
                out.append(Leaf(f"tools[{i}].description", ("tools", i, "description"), t.description))
        _leaves(payload.params, ("params",), "params", 0, out)
    return out


def set_path(data: Any, path: tuple[str | int, ...], value: Any) -> None:
    for p in path[:-1]:
        data = data[p]
    data[path[-1]] = value
