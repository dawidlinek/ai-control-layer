"""Scan report types shared by every model-artifact walker.

Nothing in here ever carries raw file content: attacker-controlled strings (member names, global names, header
facts) are sanitised and bounded by `sanitize` before they reach a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

from acl.contracts.common import Severity

Verdict = Literal["safe", "malicious", "blocked_format", "suspicious"]

MESSAGE_LIMIT = 500
DETAIL_LIMIT = 2000

_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


def sanitize(value: object, limit: int = 200) -> str:
    """Printable-ASCII, length-bounded rendering of an attacker-controlled value."""
    text = value if isinstance(value, str) else str(value)
    out = "".join(ch if " " <= ch <= "~" else "?" for ch in text[: limit + 1])
    if len(out) > limit:
        out = out[: max(limit - 3, 0)] + "..."
    return out


@dataclass(frozen=True, slots=True)
class ScanFinding:
    rule_id: str
    severity: Severity
    message: str
    detail: str | None = None
    cve: tuple[str, ...] = ()
    malicious: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "detail": self.detail,
            "cve": list(self.cve),
            "malicious": self.malicious,
        }


def make_finding(
    rule_id: str,
    severity: Severity,
    message: str,
    *,
    detail: str | None = None,
    cve: tuple[str, ...] = (),
    malicious: bool = False,
) -> ScanFinding:
    """Build a finding with message/detail sanitised and bounded."""
    return ScanFinding(
        rule_id=rule_id,
        severity=severity,
        message=sanitize(message, MESSAGE_LIMIT),
        detail=None if detail is None else sanitize(detail, DETAIL_LIMIT),
        cve=cve,
        malicious=malicious,
    )


@dataclass(frozen=True, slots=True)
class FormatException:
    """Policy-granted exception for a blocked format, matched by the file's sha256."""

    sha256: str
    reason: str
    formats: tuple[str, ...] = ()
    expires: date | None = None


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    allowed_formats: tuple[str, ...] = ("safetensors", "gguf")
    exceptions: tuple[FormatException, ...] = ()
    hf_repo_allowlist: tuple[str, ...] = ()
    opcode_globs: tuple[tuple[str, str], ...] = ()
    max_file_bytes: int = 8 * 1024**3
    max_pickle_bytes: int = 256 * 1024**2
    max_archive_members: int = 10_000
    max_uncompressed_bytes: int = 32 * 1024**3
    min_torch_version: str = "2.6.0"


@dataclass(slots=True)
class ScanReport:
    filename: str
    sha256: str
    size: int
    format_detected: str
    verdict: Verdict
    findings: list[ScanFinding] = field(default_factory=list)
    pickle_globals: list[str] = field(default_factory=list)
    exception: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "size": self.size,
            "format_detected": self.format_detected,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "pickle_globals": list(self.pickle_globals),
            "exception": self.exception,
        }

    def rule_ids(self) -> list[str]:
        return [f.rule_id for f in self.findings]
