"""Shared helpers for the deterministic controls (1D): which text to scan, entropy, value hashing.

Convention (see `acl.engine.text`): after the normalise phase, later controls inspect the normalised
payload published in `ctx.attributes["payload"]` (falling back to `ctx.payload` when the normaliser is
not enabled) plus the *decoded views* in `ctx.attributes["decoded_views"]`
(`list[{field, start, end, text}]`; start/end span the encoded token in the normalised text).

A hit inside a decoded view is reported against the span of the whole encoded token, so that a
transform replaces the token as a unit. A hit that only exists after joining line breaks (`joined`
scan texts) is reported against the original span covering both lines.
"""

from __future__ import annotations

import math
import os
import re
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from acl.contracts.canonical import value_hash
from acl.contracts.inspection import InspectionContext, Payload
from acl.engine.text import iter_texts

DEV_SALT = "dev-only-salt-change-me"


# --------------------------------------------------------------------------- hits


@dataclass(frozen=True, slots=True)
class Hit:
    """A detected span inside one scanned text. `value` is in-memory only (never logged or audited)."""

    entity: str
    start: int
    end: int
    value: str
    score: float = 1.0
    rule: str = ""


# --------------------------------------------------------------------------- scan texts


@dataclass(frozen=True, slots=True)
class ScanText:
    """One text to scan plus the mapping from match offsets back to the payload field's text."""

    field: str
    text: str
    kind: str = "text"  # text | view | joined
    span: tuple[int, int] | None = None  # view: span of the encoded token in the field's text
    index_map: tuple[int, ...] | None = None  # joined: joined offset -> original offset
    breaks: tuple[int, ...] = ()  # joined: offsets in the joined text where two lines were glued

    def locate(self, start: int, end: int) -> tuple[int, int]:
        """Span in the *field's* text for a match [start, end) in `self.text`."""
        if self.kind == "view" and self.span is not None:
            return self.span
        if self.kind == "joined" and self.index_map is not None:
            return self.index_map[start], self.index_map[end - 1] + 1
        return start, end

    def crosses_break(self, start: int, end: int) -> bool:
        """For joined texts: does [start, end) contain a glue point (else the match is already found directly)."""
        i = bisect_left(self.breaks, start + 1)
        return i < len(self.breaks) and self.breaks[i] < end


_GLUE = re.compile(r"[ \t\\\"'+`]*\r?\n[ \t\\\"'+`]*")


def join_lines(text: str) -> tuple[str, tuple[int, ...], tuple[int, ...]] | None:
    """Remove single line breaks (and trailing `\\`, quotes, `+` string-concat markers) from `text`.

    Returns (joined, index_map, breaks) or None when nothing was glued. Blank lines are kept.
    """
    if "\n" not in text:
        return None
    out: list[str] = []
    idx: list[int] = []
    breaks: list[int] = []
    pos = 0
    total = 0
    glued = False
    for m in _GLUE.finditer(text):
        nxt = text[m.end() : m.end() + 1]
        if nxt in ("\n", "\r") or m.start() == 0 or m.end() == len(text):
            continue  # paragraph break / leading / trailing newline: not a glue point
        chunk = text[pos : m.start()]
        out.append(chunk)
        idx.extend(range(pos, m.start()))
        total += len(chunk)
        breaks.append(total)
        pos = m.end()
        glued = True
    if not glued:
        return None
    out.append(text[pos:])
    idx.extend(range(pos, len(text)))
    return "".join(out), tuple(idx), tuple(breaks)


def normalised_payload(ctx: InspectionContext) -> Payload:
    p = ctx.attributes.get("payload")
    if isinstance(p, BaseModel) and getattr(p, "kind", None) == ctx.payload.kind:
        return p  # type: ignore[return-value]
    return ctx.payload


def decoded_views(ctx: InspectionContext) -> list[dict[str, Any]]:
    views = ctx.attributes.get("decoded_views")
    return list(views) if views else []


def scan_texts(ctx: InspectionContext, *, views: bool = True, joined: bool = False) -> list[ScanText]:
    """Texts to scan: normalised payload texts, optionally line-joined variants and decoded views.

    The result is memoised in the context's scratch space (`attributes`), because several controls of the
    same phase ask for the same list; callers must treat it as read-only.
    """
    payload = normalised_payload(ctx)
    cache: dict = ctx.attributes.setdefault("_scan_cache", {})
    key = (id(payload), id(ctx.attributes.get("decoded_views")), views, joined)
    cached = cache.get(key)
    if cached is not None:
        return cached
    out = _build_scan_texts(ctx, payload, views, joined)
    cache[key] = out
    return out


def _build_scan_texts(ctx: InspectionContext, payload: Payload, views: bool, joined: bool) -> list[ScanText]:
    out: list[ScanText] = []
    for field, text in iter_texts(payload):
        if not text:
            continue
        out.append(ScanText(field, text))
        if joined:
            j = join_lines(text)
            if j is not None:
                out.append(ScanText(field, j[0], "joined", None, j[1], j[2]))
    if views:
        for v in decoded_views(ctx):
            out.append(ScanText(v["field"], v["text"], "view", (v["start"], v["end"])))
    return out


# --------------------------------------------------------------------------- math / hashing


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def value_salt(deps: Any) -> str:
    """Salt for `value_hash`: settings (via control deps) → env `ACL_VALUE_HASH_SALT` → dev default."""
    settings = deps.get("settings") if deps is not None else None
    raw = getattr(settings, "value_hash_salt", None)
    if raw is not None:
        secret = raw.get_secret_value() if hasattr(raw, "get_secret_value") else str(raw)
        if secret:
            return secret
    return os.environ.get("ACL_VALUE_HASH_SALT") or DEV_SALT


def hash_value(salt: str, value: str) -> str:
    return value_hash(value, salt)


def preset_name(ctx: InspectionContext) -> str:
    return str(ctx.preset.value)
