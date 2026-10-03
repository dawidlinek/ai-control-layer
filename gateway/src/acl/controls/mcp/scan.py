"""Tool-description poisoning scanner (SEC-MCP-01).

Looks for what a legitimate tool description never needs: hidden/imperative instructions aimed at the model
(`<IMPORTANT>`, "do not tell the user"), steering towards other tools, references to credential files
(`~/.ssh`, `.env`), exfiltration instructions, invisible characters (zero-width, bidi, Unicode tags), Base64
blobs, HTML comments and oversized text. Results are value-free: a hit is `(kind, detail)` where `detail`
is a stable rule label, never the matched text.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- invisible characters

_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0E),  # variation selectors except FE0F (emoji presentation)
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),  # Unicode tag characters (ASCII smuggling)
    (0xE0100, 0xE01EF),
)
_ZWJ = 0x200D


def count_invisible(text: str) -> int:
    n = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp < 0xAD:
            continue
        if not any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES):
            continue
        if cp == _ZWJ and 0 < i < len(text) - 1 and ord(text[i - 1]) > 0x2000 and ord(text[i + 1]) > 0x2000:
            continue  # joiner inside an emoji / script sequence
        n += 1
    return n


# --------------------------------------------------------------------------- patterns (bounded quantifiers only)

_I = re.IGNORECASE
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "hidden_instruction_tag",
        re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|override|assistant)\s*>", _I),
    ),
    ("hidden_instruction_tag", re.compile(r"\[\s*/?\s*(?:system|important|instructions?|inst)\s*\]", _I)),
    (
        "concealment",
        re.compile(
            r"\b(?:do\s*n[o']?t|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|notify|"
            r"notifying|reveal|revealing|show|showing|let)\b[^.\n]{0,40}\b(?:user|human|person|operator|anyone)\b",
            _I,
        ),
    ),
    ("concealment", re.compile(r"\b(?:silently|secretly|covertly|stealthily)\b", _I)),
    ("concealment", re.compile(r"\b(?:hide|conceal)\s+(?:this|it|the\s+(?:fact|action|call))\b", _I)),
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all|any|other|"
            r"system)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?|polic(?:y|ies)|guidelines?)\b",
            _I,
        ),
    ),
    (
        "role_hijack",
        re.compile(r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(?:the\s+)?(?:system|admin))\b", _I),
    ),
    (
        "sensitive_path",
        re.compile(
            r"(?:~|\$home|\$\{home\})?[/\\]?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?<![\w.])\.env\b|"
            r"\.aws[/\\]credentials|/etc/(?:passwd|shadow)|\.npmrc\b|\.netrc\b|\.git-credentials|\bmcp\.json\b|"
            r"\bcredentials\.json\b|\bprivate[ _-]key\b",
            _I,
        ),
    ),
    (
        "tool_steering",
        re.compile(
            r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|the)\s+(?:tool|function)\b[^.\n]{0,80}"
            r"\b(?:read|open|cat|fetch|call|send|run|execute)\b",
            _I,
        ),
    ),
    (
        "tool_steering",
        re.compile(
            r"\b(?:instead\s+of|rather\s+than)\s+(?:using\s+|calling\s+)?(?:the\s+)?[`'\"\w.-]{1,64}\s+tool\b", _I
        ),
    ),
    (
        "tool_steering",
        re.compile(
            r"\b(?:when|whenever|if)\b[^.\n]{0,40}\b(?:tool|function)\b[^.\n]{0,40}\bis\s+(?:used|called|invoked|"
            r"available)\b[^.\n]{0,80}\b(?:also|must|should|always)\b",
            _I,
        ),
    ),
    (
        "tool_steering",
        re.compile(
            r"\b(?:always|must|should)\s+(?:first\s+)?(?:call|use|invoke)\b[^.\n]{0,40}\b(?:other|another)\s+tool\b", _I
        ),
    ),
    (
        "exfil_instruction",
        re.compile(
            r"\b(?:send|forward|post|upload|email|exfiltrate|transmit|leak)\b[^.\n]{0,80}\b(?:to|at|via)\b[^.\n]{0,60}"
            r"(?:https?://|@[\w.-]{1,60}\.\w{2,}|\bwebhook\b|\bpastebin\b)",
            _I,
        ),
    ),
    (
        "exfil_instruction",
        re.compile(
            r"\b(?:pass|include|put|add|append|attach)\b[^.\n]{0,60}\b(?:content|contents|output|key|token|secret|"
            r"password|credentials?|history|conversation)\b[^.\n]{0,60}\b(?:in|into|as|to|with)\b[^.\n]{0,40}"
            r"\b(?:param(?:eter)?|argument|field|header|query)\b",
            _I,
        ),
    ),
    ("html_comment", re.compile(r"<!--[\s\S]{0,2000}?-->")),
)

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=_-])")


def _base64_blob(text: str, min_len: int) -> bool:
    for m in _B64.finditer(text):
        token = m.group(0).rstrip("=")
        if len(token) < min_len:
            continue
        if not (any(c.isupper() for c in token) and any(c.islower() for c in token)):
            continue  # hex digests, identifiers, snake_case
        if not (any(c.isdigit() for c in token) or "+" in token or "/" in token):
            continue
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if raw:
            return True
    return False


# --------------------------------------------------------------------------- schema strings

_SKIP_KEYS = frozenset({"type", "$schema", "$ref", "$id", "format", "required", "additionalProperties"})


def _schema_strings(node: Any, depth: int = 0) -> Iterator[str]:
    """String leaves of a JSON Schema that the model can read (descriptions, titles, defaults, enums...)."""
    if depth > 24:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if k in _SKIP_KEYS:
                continue
            if isinstance(v, dict) and k in ("properties", "$defs", "definitions", "patternProperties"):
                for sub in v.values():  # property names are identifiers, not prose
                    yield from _schema_strings(sub, depth + 1)
            else:
                yield from _schema_strings(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _schema_strings(v, depth + 1)


# --------------------------------------------------------------------------- scan


@dataclass(frozen=True, slots=True)
class ScanHit:
    kind: str  # poisoned | invisible_chars | base64_blob | oversized | invalid_name
    detail: str  # stable label, no matched text
    where: str = "description"  # description | schema | name


_NAME_OK = re.compile(r"^[A-Za-z0-9_.\-/]{1,128}$")


def scan_text(text: str, *, where: str = "description", max_len: int = 4000, base64_min_len: int = 40) -> list[ScanHit]:
    hits: list[ScanHit] = []
    if not text:
        return hits
    if len(text) > max_len:
        hits.append(ScanHit("oversized", "description_too_long", where))
    n = count_invisible(text)
    if n:
        hits.append(ScanHit("invisible_chars", "zero_width_or_tag_characters", where))
    folded = unicodedata.normalize("NFKC", text)
    seen: set[str] = set()
    for variant in (text, folded) if folded != text else (text,):
        for label, pattern in _RULES:
            if label not in seen and pattern.search(variant):
                seen.add(label)
                hits.append(ScanHit("poisoned", label, where))
    if _base64_blob(text, base64_min_len):
        hits.append(ScanHit("base64_blob", "base64_encoded_blob", where))
    return hits


def scan_tool(
    name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
    *,
    max_len: int = 4000,
    base64_min_len: int = 40,
) -> list[ScanHit]:
    hits: list[ScanHit] = []
    if not _NAME_OK.match(name or ""):
        hits.append(ScanHit("invalid_name", "tool_name_charset", "name"))
    hits.extend(scan_text(description or "", max_len=max_len, base64_min_len=base64_min_len))
    for s in _schema_strings(input_schema or {}):
        hits.extend(scan_text(s, where="schema", max_len=max_len, base64_min_len=base64_min_len))
    uniq: list[ScanHit] = []
    for h in hits:
        if h not in uniq:
            uniq.append(h)
    return uniq


def scan_strings(values: Iterable[str], *, where: str = "text", max_len: int = 4000) -> list[ScanHit]:
    out: list[ScanHit] = []
    for v in values:
        out.extend(scan_text(v, where=where, max_len=max_len))
    return out
