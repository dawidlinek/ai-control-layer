"""Secret detection rules (gitleaks-style) plus a high-entropy token heuristic.

Each rule has lowercase `keywords`; a rule's regex only runs when one of them occurs in the lowercased
text (cheap pre-filter, like gitleaks). Patterns are linear-time `re` expressions written for this
module. The value group (`group`) is the part reported as the finding span.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from acl.controls.normalise.scan import Hit, shannon_entropy


@dataclass(frozen=True, slots=True)
class SecretRule:
    entity: str
    regex: re.Pattern[str]
    keywords: tuple[str, ...] = ()
    group: int = 0
    min_entropy: float = 0.0


def _r(
    entity: str, pattern: str, keywords: tuple[str, ...] = (), group: int = 0, min_entropy: float = 0.0
) -> SecretRule:
    return SecretRule(entity, re.compile(pattern), tuple(k.lower() for k in keywords), group, min_entropy)


_PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|changeme\w*|change_me\w*|your[_-].*|"
    r"example\w*|placeholder\w*|password\w{0,3}|secret\w{0,3}|redacted|none|null|true|false|dummy\w*|test\w{0,4}|"
    r"todo|fixme|env\.\w+|process\.env\S*|os\.environ\S*|getenv\S*|config\.\w+|settings\.\w+)$"
)
_CODE_REF = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")

RULES: tuple[SecretRule, ...] = (
    # cloud providers
    _r("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", ("AKIA", "ASIA", "ABIA", "ACCA")),
    _r(
        "AWS_SECRET_KEY",
        r"(?i)\baws[\w .-]{0,24}?(?:secret|sk)[\w .-]{0,16}?[\"'\s:=]{1,5}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        ("aws",),
        1,
        3.5,
    ),
    _r("GCP_API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b", ("AIza",)),
    _r("GCP_OAUTH_TOKEN", r"\bya29\.[0-9A-Za-z_\-]{30,}", ("ya29.",)),
    _r("AZURE_STORAGE_KEY", r"(?i)AccountKey=([A-Za-z0-9+/]{40,}={0,2})", ("AccountKey",), 1),
    _r("AZURE_AD_SECRET", r"\b[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{31,34}\b", ("8Q~",)),
    _r("AZURE_SAS_TOKEN", r"(?i)[?&]sig=([A-Za-z0-9%+/]{43,}={0,3})", ("sig=",), 1),
    # source hosting / collaboration
    _r("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    _r("GITHUB_PAT", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b", ("github_pat_",)),
    _r(
        "GITLAB_TOKEN",
        r"\bgl(?:pat|ptt|rt|oas|dt|imt|agent|cbt|soat)-[A-Za-z0-9_\-]{20,}\b",
        ("glpat-", "glptt-", "glrt-", "gloas-", "gldt-", "glimt-", "glagent-", "glcbt-", "glsoat-"),
    ),
    _r("SLACK_TOKEN", r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b", ("xox",)),
    _r(
        "SLACK_WEBHOOK",
        r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,}",
        ("hooks.slack.com",),
    ),
    # payments / SaaS
    _r("STRIPE_KEY", r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{20,99}\b", ("sk_live", "sk_test", "rk_live", "rk_test")),
    _r("TWILIO_KEY", r"\bSK[0-9a-fA-F]{32}\b", ("SK",)),
    _r("SENDGRID_KEY", r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b", ("SG.",)),
    _r("NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{36}\b", ("npm_",)),
    _r("PYPI_TOKEN", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", ("pypi-",)),
    _r("DOCKERHUB_PAT", r"\bdckr_pat_[A-Za-z0-9_\-]{20,}", ("dckr_pat_",)),
    # AI providers
    _r("ANTHROPIC_KEY", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{32,}", ("sk-ant-",)),
    _r("OPENAI_KEY", r"\bsk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_\-]{32,}", ("sk-proj-", "sk-svcacct-", "sk-admin-")),
    _r("OPENAI_KEY", r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b", ("T3BlbkFJ",)),
    _r("OPENAI_KEY", r"\bsk-[A-Za-z0-9]{40,}\b", ("sk-",)),
    _r("HUGGINGFACE_TOKEN", r"\bhf_[A-Za-z0-9]{30,}\b", ("hf_",)),
    # generic material
    _r("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", ("eyj",)),
    _r(
        "PRIVATE_KEY",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,8192}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)?",
        ("private key",),
    ),
    _r(
        "BASIC_AUTH_URL",
        r"\b[a-z][a-z0-9+.-]{1,12}://[^\s:/@\"']{1,64}:([^\s:/@\"']{4,64})@[A-Za-z0-9.-]+",
        ("://",),
        1,
    ),
    _r("BEARER_TOKEN", r"(?i)\bauthorization\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9._~+/=-]{20,})", ("bearer",), 1, 3.0),
)

# `password=...`, `api_key: "..."` style assignments
_ASSIGN = re.compile(
    r"(?i)\b(?P<key>[a-z0-9_.-]{0,24}(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"
    r"access[_-]?token|client[_-]?secret|private[_-]?key|token))[\"']?\s*(?:[:=]|=>)\s*(?P<q>[\"']?)(?P<val>[^\s\"'`<>,;]{6,200})"
)
_ASSIGN_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "api-key",
    "apikey",
    "access_key",
    "access-key",
    "token",
    "private_key",
)
_PASSWORDISH = ("password", "passwd", "pwd")

_PEM_BLOCK = re.compile(r"-----BEGIN (?!(?:[A-Z]+ )*PRIVATE KEY)[A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----")
_SRI_PREFIXES = ("sha512-", "sha384-", "sha256-", "sha1-")
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9_+/=-]{32,200}")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


_LOWER_RUN = re.compile(r"[a-z]+")


def _looks_like_identifier(tok: str) -> bool:
    """camelCase / snake_case names are built from words (long lowercase runs); random tokens are not."""
    alnum = [c for c in tok if c.isalnum()]
    if not alnum:
        return True
    upper = sum(c.isupper() for c in alnum) / len(alnum)
    runs = _LOWER_RUN.findall(tok)
    mean_run = sum(len(r) for r in runs) / len(runs) if runs else 0.0
    return upper < 0.12 or mean_run >= 3.3


def _assign_hits(text: str, low: str) -> Iterable[Hit]:
    if not any(k in low for k in _ASSIGN_KEYWORDS):
        return
    for m in _ASSIGN.finditer(text):
        val = m.group("val")
        if _PLACEHOLDER_VALUES.match(val) or _CODE_REF.match(val):
            continue
        if any(c in val for c in "()[]{}$%"):
            continue
        quoted = bool(m.group("q"))
        key = m.group("key").lower()
        has_mixed = any(c.isdigit() for c in val) or any(not c.isalnum() for c in val)
        if any(w in key for w in _PASSWORDISH):
            if not (quoted or has_mixed) or len(val) < 8:
                continue
        else:
            if len(val) < 16 or shannon_entropy(val) < 3.3 or not (has_mixed or quoted):
                continue
        yield Hit("PASSWORD_ASSIGNMENT", m.start("val"), m.end("val"), val, 0.8, "generic-assignment")


def find_secrets(
    text: str,
    *,
    entropy: bool = True,
    entropy_threshold: float = 4.3,
    entropy_min_len: int = 32,
    skip_spans: Iterable[tuple[int, int]] = (),
) -> list[Hit]:
    """All secret hits in `text` (non-overlapping, ordered); `skip_spans` are exempt from the entropy heuristic."""
    if len(text) < 8:
        return []
    low = text.lower()
    hits: list[Hit] = []
    for rule in RULES:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            val = m.group(rule.group)
            if val is None:
                continue
            if rule.group and _PLACEHOLDER_VALUES.match(val):
                continue
            if rule.min_entropy and shannon_entropy(val) < rule.min_entropy:
                continue
            hits.append(Hit(rule.entity, m.start(rule.group), m.end(rule.group), val, 0.99, rule.entity))
    hits.extend(_assign_hits(text, low))

    if entropy and len(text) >= entropy_min_len:
        skips = list(skip_spans)
        if "-----begin" in low:  # public material in PEM armour (certificates) is not a credential
            skips.extend(m.span() for m in _PEM_BLOCK.finditer(text))
        for m in _ENTROPY_TOKEN.finditer(text):
            tok = m.group(0)
            if len(tok) < entropy_min_len:
                continue
            if any(m.start() < e and s < m.end() for s, e in skips):
                continue
            if tok.lower().startswith(_SRI_PREFIXES) or text[max(0, m.start() - 8) : m.start()].lower().endswith(
                "base64,"
            ):
                continue  # subresource-integrity hashes, data: URIs
            if _HEX_ONLY.match(tok) or _UUID.match(tok):  # hashes / ids are not credentials
                continue
            if not (any(c.islower() for c in tok) and any(c.isupper() for c in tok) and any(c.isdigit() for c in tok)):
                continue
            if shannon_entropy(tok) >= entropy_threshold and not _looks_like_identifier(tok):
                hits.append(Hit("HIGH_ENTROPY_TOKEN", m.start(), m.end(), tok, 0.7, "entropy"))

    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    out: list[Hit] = []
    for h in hits:
        if out and h.start < out[-1].end:
            continue  # keep the earliest/longest of overlapping hits
        out.append(h)
    return out
