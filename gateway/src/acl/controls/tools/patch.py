"""Target paths of a patch argument (OpenCode `patch` / `apply_patch`, unified diffs) for SEC-TOOL-01.

    patch_targets(text) -> list[str] | None

Every file a patch creates, changes, deletes or moves to must be visible to the path checker, so it can apply the
same rules as `opencode.write` (workspace only, protected locations, persistence files). Recognised headers:

  * OpenCode envelope: `*** Add File: p`, `*** Update File: p`, `*** Delete File: p`, `*** Move to: p`
  * unified / git diffs: `--- a/p`, `+++ b/p` (`/dev/null` ignored, `a/` `b/` prefixes stripped), `diff --git a/p b/q`,
    git extended headers `rename from/to p`, `copy from/to p`

`None` means "cannot tell what this patch touches" (no header at all, an empty path, a non-string): the caller blocks
(fail closed). Unknown `*** ` directives are rejected too, so a future envelope verb cannot smuggle a target past the
parser.
"""

from __future__ import annotations

import re

MAX_TARGETS = 500

_ENVELOPE = re.compile(r"^\*\*\* (Add File|Update File|Delete File|Move to):(.*)$")
_ENVELOPE_FRAME = re.compile(r"^\*\*\* (?:Begin Patch|End Patch|End of File)\s*$")
_UNIFIED = re.compile(r"^(?:---|\+\+\+) (.*)$")
_GIT_HEADER = re.compile(r"^diff --git (.+)$")
_GIT_EXTENDED = re.compile(r"^(?:rename|copy) (?:from|to) (.+)$")


def _clean(raw: str, *, strip_prefix: bool) -> str | None:
    p = raw.strip()
    if "\t" in p:  # `+++ b/x.py\t2024-01-01 00:00:00` (timestamp after a tab)
        p = p.split("\t", 1)[0].strip()
    if len(p) >= 2 and p[0] == p[-1] == '"':
        p = p[1:-1]  # git quotes unusual names; escapes are kept (stricter, never laxer)
    if not p:
        return None
    if strip_prefix and re.match(r"^[ab]/", p):
        p = p[2:]
        if not p:
            return None
    return p


def patch_targets(text: object) -> list[str] | None:
    """Every target path of the patch in order of appearance, or None when the patch cannot be understood."""
    if not isinstance(text, str) or not text.strip():
        return None
    out: list[str] = []
    in_envelope = False

    def add(path: str | None) -> bool:
        if path is None:
            return False
        if path not in out:
            out.append(path)
        return True

    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("*** "):
            m = _ENVELOPE.match(line.rstrip("\r"))
            if m:
                in_envelope = True
                if not add(_clean(m.group(2), strip_prefix=False)):
                    return None
                continue
            if _ENVELOPE_FRAME.match(line):
                in_envelope = True
                continue
            if not in_envelope:
                # a unified-diff `*** ` context header (old-style context diff) is not supported either
                return None
            return None  # unknown envelope directive: fail closed
        if in_envelope:
            continue  # envelope content lines start with `+`, `-`, ` ` or `@@`
        # a file header is a `--- old` line directly followed by `+++ new`; a lone `--- x` is a removed hunk line
        # (`-- x`). Pairs inside hunk content are checked as well: that can only add targets, never hide one.
        pair = line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")
        if pair or (line.startswith("+++ ") and i > 0 and lines[i - 1].startswith("--- ")):
            m = _UNIFIED.match(line)
            target = _clean(m.group(1), strip_prefix=True) if m else None
            if target is None:
                return None
            if target != "/dev/null":
                add(target)
            continue
        m = _GIT_HEADER.match(line)
        if m:
            parts = m.group(1).split(" b/", 1)
            if len(parts) == 2:
                add(_clean(parts[0], strip_prefix=True))
                add(_clean("b/" + parts[1], strip_prefix=True))
            continue
        m = _GIT_EXTENDED.match(line)
        if m and not add(_clean(m.group(1), strip_prefix=False)):
            return None
    if len(out) > MAX_TARGETS:
        return None  # an approver could not review it, and the checker would not finish in time
    return out or None
