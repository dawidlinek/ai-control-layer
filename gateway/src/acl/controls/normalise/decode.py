"""Text normalisation and Base64 / hex / URL-encoding decoders (stage 0, concept §6.2).

Pure functions, no I/O. `normalise_text` rewrites one text; `find_views` finds encoded segments in the
(already normalised) text and returns their decoded content so later controls can rescan it.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# ---------------------------------------------------------------- invisible characters


_STRIP_RANGES = [
    (0x00, 0x08),
    (0x0B, 0x0C),
    (0x0E, 0x1F),  # C0 controls except \t \n \r
    (0x7F, 0x7F),
    (0x80, 0x9F),  # C1 controls
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180E),
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x206F),  # word joiner, invisible operators, deprecated format chars
    (0x3164, 0x3164),
    (0xFE00, 0xFE0E),  # variation selectors (FE0F, emoji presentation, is kept)
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP
    (0xFFA0, 0xFFA0),
    (0xFFF9, 0xFFFB),
    (0xE0000, 0xE007F),  # Unicode tag characters (ASCII smuggling)
    (0xE0100, 0xE01EF),  # variation selectors supplement
]
_STRIP_TABLE: dict[int, None] = {cp: None for lo, hi in _STRIP_RANGES for cp in range(lo, hi + 1)}
# a regex scan for "anything to strip?" is far cheaper than translate() with a large table
_STRIP_RE = re.compile("[" + "".join(f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in _STRIP_RANGES) + "]")
_TAG_RUN = re.compile("[\U000e0020-\U000e007e]+")
_ANY_TAG = re.compile("[\U000e0000-\U000e007f]")

# chat-template special tokens: ChatML / Llama / Gemma / gpt-oss "harmony" / DeepSeek, ...
_TEMPLATE_TOKEN = re.compile(
    r"<\|[^\s<>|]{1,40}\|>"
    r"|\[/?INST\]|<</?SYS>>|\[/?SYS\]"
    r"|</?(?:start|end)_of_turn>"
    r"|<\|?/?(?:begin|end)_of_(?:text|sentence)\|?>"
)

_UNICODE_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")


@dataclass(slots=True)
class NormResult:
    text: str
    changed: bool = False
    forged_tokens: int = 0
    hidden_chars: int = 0
    # decoded ASCII smuggled in tag characters: (position in the normalised text, decoded text)
    smuggled: list[tuple[int, str]] = field(default_factory=list)


def _decode_tags(run: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def _strip_invisible(s: str) -> tuple[str, int, list[tuple[int, str]]]:
    """Remove invisible characters. Returns (clean, removed_count, [(clean_pos, decoded_tag_text)])."""
    smuggled: list[tuple[int, str]] = []
    if _ANY_TAG.search(s) is None:
        if _STRIP_RE.search(s) is None:
            return s, 0, smuggled
        clean = s.translate(_STRIP_TABLE)
        return clean, len(s) - len(clean), smuggled
    parts: list[str] = []
    length = 0
    pos = 0
    removed = 0
    for m in _TAG_RUN.finditer(s):
        seg = s[pos : m.start()].translate(_STRIP_TABLE)
        removed += (m.start() - pos) - len(seg)
        parts.append(seg)
        length += len(seg)
        smuggled.append((length, _decode_tags(m.group(0))))
        removed += len(m.group(0))
        pos = m.end()
    tail = s[pos:].translate(_STRIP_TABLE)  # also removes tag chars outside the printable-tag range
    removed += (len(s) - pos) - len(tail)
    parts.append(tail)
    return "".join(parts), removed, smuggled


def _unescape_json_unicode(s: str) -> str:
    """Resolve `\\uXXXX` escapes of ordinary characters in JSON text (keeps `\\u0022`, `\\u005c`, controls)."""
    if "\\u" not in s:
        return s

    def repl(m: re.Match[str]) -> str:
        cp = int(m.group(1), 16)
        if cp < 0x20 or cp in (0x22, 0x5C) or 0xD800 <= cp <= 0xDFFF:
            return m.group(0)
        return chr(cp)

    return _UNICODE_ESC.sub(repl, s)


def normalise_text(text: str, *, json_args: bool = False, strip_templates: bool = True) -> NormResult:
    """NFKC → invisible/tag stripping → chat-template token stripping (→ JSON `\\u` unescape)."""
    s = text
    res = NormResult(text)
    if not s.isascii() and not unicodedata.is_normalized("NFKC", s):
        s = unicodedata.normalize("NFKC", s)
    if json_args:
        s = _unescape_json_unicode(s)
    # fast path: plain printable ASCII without C0 controls needs no invisible-char pass
    if not s.isascii() or not s.isprintable():
        s, removed, smuggled = _strip_invisible(s)
        res.hidden_chars = removed
        res.smuggled = smuggled
    if strip_templates and ("<" in s or "[" in s):
        spans = [m.span() for m in _TEMPLATE_TOKEN.finditer(s)]
        if spans:
            res.forged_tokens = len(spans)
            out: list[str] = []
            prev = 0
            for a, b in spans:
                out.append(s[prev:a])
                prev = b
            out.append(s[prev:])
            # shift smuggled positions left by the removed template tokens
            if res.smuggled:
                res.smuggled = [(_remap(pos, spans), t) for pos, t in res.smuggled]
            s = "".join(out)
    res.text = s
    res.changed = s != text
    return res


def _remap(pos: int, spans: list[tuple[int, int]]) -> int:
    shift = 0
    for a, b in spans:
        if pos >= b:
            shift += b - a
        elif pos > a:
            shift += pos - a
            break
        else:
            break
    return pos - shift


def count_template_tokens(text: str) -> int:
    return len(_TEMPLATE_TOKEN.findall(text)) if ("<" in text or "[" in text) else 0


# ---------------------------------------------------------------- decoded views

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
_B64_BLOCK = re.compile(
    r"(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/]{8,}={0,2}[ \t]*\r?\n[ \t]*)+[A-Za-z0-9+/]{4,}={0,2}(?![A-Za-z0-9+/_-])"
)
_HEX_TOKEN = re.compile(r"(?<![0-9A-Za-z])(?:0x)?((?:[0-9A-Fa-f]{2}){6,})(?![0-9A-Za-z])")
_HEX_ESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_PCT_TOKEN = re.compile(r"\S*%[0-9A-Fa-f]{2}\S*")
_PCT_ESC = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass(frozen=True, slots=True)
class View:
    start: int
    end: int
    text: str
    encoding: str


def _printable_text(raw: bytes, *, min_len: int = 6) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < min_len:
        return None
    good = sum(1 for c in text if c.isprintable() or c in "\t\n\r")
    if good / len(text) < 0.95:
        return None
    if len(set(text)) < 3:
        return None
    return text


def try_base64(token: str, *, min_len: int = 6) -> str | None:
    """Decode a Base64 / Base64url token to printable text, else None."""
    t = token.strip().rstrip("=")
    if len(t) < 8 or len(t) % 4 == 1:
        return None
    std = ("+" in t) or ("/" in t)
    url = ("-" in t) or ("_" in t)
    if std and url:
        return None
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.urlsafe_b64decode(t) if url else base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(raw, min_len=min_len)


def try_hex(token: str, *, min_len: int = 6) -> str | None:
    t = token[2:] if token.lower().startswith("0x") else token
    t = t.replace("\\x", "")
    if len(t) % 2:
        return None
    try:
        raw = bytes.fromhex(t)
    except ValueError:
        return None
    return _printable_text(raw, min_len=min_len)


def try_percent(token: str) -> str | None:
    if len(_PCT_ESC.findall(token)) < 2:
        return None
    dec = unquote(token)
    if dec == token:
        return None
    good = sum(1 for c in dec if c.isprintable() or c in "\t\n\r")
    return dec if good / max(len(dec), 1) >= 0.95 else None


def _scan_once(text: str, *, min_b64: int, min_hex: int) -> list[View]:
    views: list[View] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return not any(a < y and x < b for x, y in taken)

    if "\n" in text:  # multi-line (MIME style) Base64 blocks
        for m in _B64_BLOCK.finditer(text):
            joined = re.sub(r"\s+", "", m.group(0))
            dec = try_base64(joined)
            if dec is not None and free(m.start(), m.end()):
                views.append(View(m.start(), m.end(), dec, "base64"))
                taken.append((m.start(), m.end()))
    if "%" in text:
        for m in _PCT_TOKEN.finditer(text):
            dec = try_percent(m.group(0))
            if dec is not None and free(m.start(), m.end()):
                views.append(View(m.start(), m.end(), dec, "url"))
                taken.append((m.start(), m.end()))
    if len(text) >= min_b64:
        for m in _B64_TOKEN.finditer(text):
            if not free(m.start(), m.end()):
                continue
            tok = m.group(0)
            dec = try_base64(tok)
            if dec is None and "/" in tok:  # token glued to a URL path: try its segments
                off = 0
                for seg in tok.split("/"):
                    if len(seg) >= min_b64:
                        d = try_base64(seg)
                        if d is not None and free(m.start() + off, m.start() + off + len(seg)):
                            a = m.start() + off
                            views.append(View(a, a + len(seg), d, "base64"))
                            taken.append((a, a + len(seg)))
                    off += len(seg) + 1
                continue
            if dec is not None:
                views.append(View(m.start(), m.end(), dec, "base64"))
                taken.append((m.start(), m.end()))
    if len(text) >= min_hex:
        for m in _HEX_TOKEN.finditer(text):
            if len(m.group(1)) < min_hex or not free(m.start(), m.end()):
                continue
            dec = try_hex(m.group(0))
            if dec is not None:
                views.append(View(m.start(), m.end(), dec, "hex"))
                taken.append((m.start(), m.end()))
        for m in _HEX_ESC.finditer(text):
            dec = try_hex(m.group(0))
            if dec is not None and free(m.start(), m.end()):
                views.append(View(m.start(), m.end(), dec, "hex"))
                taken.append((m.start(), m.end()))
    return views


def find_views(
    text: str, *, depth: int = 2, max_views: int = 32, min_b64: int = 16, min_hex: int = 12, budget: int = 65536
) -> list[View]:
    """Decoded views of encoded segments in `text`. Nested encodings share the outermost token's span."""
    out: list[View] = []
    if len(text) < 8 or depth < 1:
        return out
    if len(text) > 200_000:
        text = text[:200_000]
    for v in _scan_once(text, min_b64=min_b64, min_hex=min_hex):
        if len(out) >= max_views or budget <= 0:
            break
        out.append(v)
        budget -= len(v.text)
        frontier = [v.text]
        for _ in range(depth - 1):
            nxt: list[str] = []
            for t in frontier:
                for inner in _scan_once(t, min_b64=min_b64, min_hex=min_hex):
                    if len(out) >= max_views:
                        break
                    out.append(View(v.start, v.end, inner.text, f"{v.encoding}>{inner.encoding}"))
                    nxt.append(inner.text)
            frontier = nxt
    return out
