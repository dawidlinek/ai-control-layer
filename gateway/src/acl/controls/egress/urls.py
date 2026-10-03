"""URL / markdown extraction and exfiltration indicators for SEC-EXFIL-01 (pure functions)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from acl.controls.normalise.decode import try_base64, try_hex
from acl.controls.normalise.scan import shannon_entropy
from acl.controls.pii.detect import detect
from acl.controls.pii.vault import PLACEHOLDER_RE
from acl.controls.secrets.rules import find_secrets

# (the target class excludes `[` so that runs of unterminated `[a](` openers cannot make matching quadratic)
_MD_IMAGE = re.compile(r"!\[([^\]\n]{0,300})\]\(\s*<?([^)\s>\[]{1,2048})>?(?:\s+\"[^\"\n]*\")?\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]\n]{0,300})\]\(\s*<?([^)\s>\[]{1,2048})>?(?:\s+\"[^\"\n]*\")?\s*\)")
_MD_REF_IMAGE = re.compile(r"!\[([^\]\n]{0,300})\]\[([^\]\n]{1,100})\]")
_MD_REF_DEF = re.compile(r"(?m)^[ ]{0,3}\[([^\]\n]{1,100})\]:\s*<?(\S+?)>?(?:\s+.*)?$")
_HTML_IMG = re.compile(r"(?i)<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)[^>]*>")
_RAW_URL = re.compile(
    r"(?i)\b(?:https?|ftps?|wss?)://[^\s\"'<>`\[\]()]+|(?<![\w:/])//[a-z0-9.-]+\.[a-z]{2,}/[^\s\"'<>`()]*"
)

_ENC_VALUE = re.compile(r"^[A-Za-z0-9+/_=-]{24,}$")


@dataclass(frozen=True, slots=True)
class UrlRef:
    kind: str  # image | link | url
    url: str
    start: int  # span of the whole construct (image/link/url) in the text
    end: int


@dataclass
class Indicators:
    kinds: list[str] = field(default_factory=list)
    has_secret: bool = False

    def add(self, kind: str) -> None:
        if kind not in self.kinds:
            self.kinds.append(kind)


def _strip_trailing(url: str) -> str:
    return url.rstrip(".,;:!?'\"")


def extract_urls(text: str) -> list[UrlRef]:
    """Markdown images/links, reference-style images, HTML <img>, and raw URLs (deduplicated by span)."""
    refs: list[UrlRef] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return not any(a < y and x < b for x, y in taken)

    def add(kind: str, url: str, a: int, b: int) -> None:
        if free(a, b):
            refs.append(UrlRef(kind, url, a, b))
            taken.append((a, b))

    if "](" in text:
        for m in _MD_IMAGE.finditer(text):
            add("image", m.group(2), m.start(), m.end())
        for m in _MD_LINK.finditer(text):
            add("link", m.group(2), m.start(), m.end())
    if "][" in text:
        defs = {m.group(1).lower(): m.group(2) for m in _MD_REF_DEF.finditer(text)}
        for m in _MD_REF_IMAGE.finditer(text):
            target = defs.get(m.group(2).lower())
            if target:
                add("image", target, m.start(), m.end())
    if "<" in text and "img" in text.lower():
        for m in _HTML_IMG.finditer(text):
            add("image", m.group(1), m.start(), m.end())
    if "//" in text:
        for m in _RAW_URL.finditer(text):
            url = _strip_trailing(m.group(0))
            add("url", url, m.start(), m.start() + len(url))
    return refs


def host_of(url: str) -> str | None:
    u = url.strip()
    if u.startswith("//"):
        u = "https:" + u
    try:
        parts = urlsplit(u)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp", "ftps", "ws", "wss"):
        return None
    host = parts.hostname
    return host.lower().rstrip(".") if host else None


def host_allowed(host: str, allow: list[str]) -> bool:
    for pat in allow:
        pat = pat.lower()
        if fnmatch.fnmatchcase(host, pat):
            return True
        if pat.startswith("*.") and host == pat[2:]:
            return True
    return False


def _encoded_payload(value: str) -> bool:
    if not _ENC_VALUE.match(value):
        return False
    return try_base64(value) is not None or (len(value) % 2 == 0 and try_hex(value) is not None)


def exfil_indicators(url: str, *, max_query_entropy: float, min_entropy_len: int = 20) -> Indicators:
    """Signals that a URL carries data out: placeholders, PII, secrets, encoded or high-entropy values."""
    ind = Indicators()
    u = url.strip()
    if u.startswith("//"):
        u = "https:" + u
    try:
        parts = urlsplit(u)
    except ValueError:
        ind.add("unparseable")
        return ind

    payload_parts = [parts.path, parts.query, parts.fragment]
    decoded = [unquote(unquote(p)) for p in payload_parts if p]
    blob = "\n".join(decoded)

    if blob:
        if PLACEHOLDER_RE.search(blob):
            ind.add("placeholder")
        if detect(blob):
            ind.add("pii")
        if find_secrets(blob, entropy=False):
            ind.add("secret")
            ind.has_secret = True

    # query values (and fragment) – encoded blobs / high entropy
    pairs = parse_qsl(parts.query, keep_blank_values=True) if parts.query else []
    values = [v for _k, v in pairs]
    if parts.fragment:
        values.append(unquote(parts.fragment))
    for v in values:
        if _encoded_payload(v):
            ind.add("encoded")
        elif len(v) >= min_entropy_len and shannon_entropy(v) >= max_query_entropy:
            ind.add("high_entropy")
    # long opaque path segments (…/<base64>.png)
    for seg in parts.path.split("/"):
        seg = unquote(seg).rsplit(".", 1)[0]
        if len(seg) >= 24 and (_encoded_payload(seg) or shannon_entropy(seg) >= max_query_entropy + 0.7):
            ind.add("high_entropy_path")
    # data in the hostname (DNS exfiltration): long random-looking label
    host = (parts.hostname or "").lower()
    for label in host.split("."):
        if len(label) >= 24 and shannon_entropy(label) >= 3.2:
            ind.add("host_label")
    return ind
