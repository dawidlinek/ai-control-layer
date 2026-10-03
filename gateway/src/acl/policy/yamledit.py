"""Round-trip YAML helpers: source locations for error reporting and structured, comment-preserving edits.

`ruamel.yaml` in round-trip mode keeps comments, quoting, key order, flow/block style and blank lines, so
a panel edit changes only the lines it touches. Used by the loader (line/column of validation errors) and
by the writer (`patch_text`, i.e. `patch_file`).
"""

from __future__ import annotations

import io
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

PathPart = str | int | Mapping[str, Any]
"""One step of a YAML path: a mapping key, a list index, or `{"id": "X"}` selecting the list item whose
`id` equals `X` (stable under re-ordering; use it for `controls`, `models`, `org_locks`)."""


class PatchError(ValueError):
    """The structured edit cannot be applied (bad path, wrong node type, unparseable YAML)."""


def rt_yaml() -> YAML:
    """The one round-trip configuration used for every write (matches the style of `policy/*.yaml`)."""
    y = YAML()  # typ="rt"
    y.preserve_quotes = True
    y.width = 4096  # never re-wrap long descriptions
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _load(text: str) -> Any:
    return rt_yaml().load(io.StringIO(text))


def _dump(doc: Any) -> str:
    buf = io.StringIO()
    rt_yaml().dump(doc, buf)
    return buf.getvalue()


# ---------------------------------------------------------------- locating


def _step(node: Any, part: PathPart) -> tuple[Any, tuple[int, int]] | None:
    """Child of `node` addressed by `part` plus its (line, column), 1-based; None if it does not exist."""
    if isinstance(node, CommentedMap):
        key = part if isinstance(part, str) and part in node else None
        if key is None and not isinstance(part, Mapping):
            key = next((k for k in node if str(k) == str(part)), None)
        if key is None:
            return None
        line, col = node.lc.key(key)
        return node[key], (line + 1, col + 1)
    if isinstance(node, CommentedSeq):
        idx = _seq_index(node, part)
        if idx is None:
            return None
        line, col = node.lc.item(idx)
        return node[idx], (line + 1, col + 1)
    return None


def _seq_index(seq: Sequence[Any], part: PathPart) -> int | None:
    if isinstance(part, int):
        return part if 0 <= part < len(seq) else None
    if isinstance(part, Mapping):
        if len(part) != 1:
            return None
        ((k, v),) = part.items()
        return next((i for i, item in enumerate(seq) if isinstance(item, Mapping) and item.get(k) == v), None)
    if isinstance(part, str):
        if part.isdigit():
            return int(part) if int(part) < len(seq) else None
        return next((i for i, item in enumerate(seq) if isinstance(item, Mapping) and item.get("id") == part), None)
    return None


@dataclass
class Locator:
    """Resolve validation-error paths to (line, column) in one document; parses the text once."""

    text: str
    _doc: Any = field(init=False, default=None)

    def __post_init__(self) -> None:
        try:
            self._doc = _load(self.text)
        except YAMLError:
            self._doc = None

    def locate(self, path: Sequence[PathPart]) -> tuple[int, int] | None:
        """Position of the deepest node of `path` that exists (pydantic adds union tags that are not in YAML)."""
        node, best = self._doc, None
        for part in path:
            got = _step(node, part)
            if got is None:
                continue
            node, best = got
        return best


# ---------------------------------------------------------------- structured edits


@dataclass(frozen=True)
class PathOp:
    """`set` (create or replace) or `delete` the node at `path`; `value` is the plain JSON-like new value."""

    op: Literal["set", "delete"]
    path: Sequence[PathPart]
    value: Any = None


def _resolve_parent(doc: Any, path: Sequence[PathPart]) -> tuple[Any, PathPart]:
    if not path:
        raise PatchError("empty path")
    node = doc
    for part in path[:-1]:
        got = _step(node, part)
        if got is None:
            raise PatchError(f"path not found at {part!r}")
        node = got[0]
    return node, path[-1]


def _coerce(old: Any, new: Any) -> Any:
    """Plain list/dict replacing a flow-style node (`stages: [a, b]`) stays flow-style."""
    flow = getattr(getattr(old, "fa", None), "flow_style", lambda: None)()
    if flow and isinstance(new, list | dict) and not isinstance(new, CommentedSeq | CommentedMap):
        node = CommentedSeq(new) if isinstance(new, list) else CommentedMap(new)
        node.fa.set_flow_style()
        return node
    return new


def _apply(doc: Any, op: PathOp) -> None:
    parent, last = _resolve_parent(doc, op.path)
    if isinstance(parent, CommentedMap):
        if isinstance(last, Mapping):
            raise PatchError("selector steps are only valid inside lists")
        key = next((k for k in parent if str(k) == str(last)), last)
        if op.op == "delete":
            if key not in parent:
                raise PatchError(f"key {last!r} not found")
            del parent[key]
        else:
            parent[key] = _coerce(
                parent.get(key), op.value
            )  # assigning to an existing key keeps its comments and position
    elif isinstance(parent, CommentedSeq):
        idx = _seq_index(parent, last)
        if op.op == "delete":
            if idx is None:
                raise PatchError(f"list item {last!r} not found")
            del parent[idx]
        elif idx is not None:
            parent[idx] = _coerce(parent[idx], op.value)
        elif isinstance(last, int) and last == len(parent):
            parent.append(op.value)
        else:
            raise PatchError(f"list item {last!r} not found")
    else:
        raise PatchError("parent is not a mapping or list")


def patch_text(text: str, ops: Sequence[PathOp]) -> str:
    """Apply `ops` to YAML `text`, preserving comments, quotes, order and layout. Returns the new text."""
    try:
        doc = _load(text)
    except YAMLError as exc:
        raise PatchError(f"existing file is not valid YAML: {getattr(exc, 'problem', exc)}") from exc
    if doc is None:
        doc = CommentedMap()
    if not isinstance(doc, CommentedMap):
        raise PatchError("top level must be a mapping")
    for op in ops:
        _apply(doc, op)
    return _dump(doc)
