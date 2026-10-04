"""Hugging Face source checks (pure, no network).

A model fetched from the Hub must be pinned to a full 40-hex commit SHA (a branch or tag can move, and a deleted
org/repo name can be re-registered by an attacker: namespace reuse) and its `org/repo` must match the allowlist.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from acl.artifacts.report import ScanFinding, make_finding, sanitize
from acl.contracts.common import Severity

_SOURCE_RE = re.compile(
    r"^hf:([A-Za-z0-9][A-Za-z0-9._-]{0,95})/([A-Za-z0-9][A-Za-z0-9._-]{0,95})@([A-Za-z0-9._/-]{1,128})$"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class HfRef:
    org: str
    repo: str
    revision: str

    @property
    def repo_id(self) -> str:
        return f"{self.org}/{self.repo}"

    @property
    def pinned(self) -> bool:
        return bool(_SHA_RE.match(self.revision))


def parse_hf_source(source: str | None) -> HfRef | None:
    """Parse `hf:org/repo@<revision>`; None when the string is not a well-formed Hugging Face source."""
    if not isinstance(source, str):
        return None
    match = _SOURCE_RE.match(source)
    if match is None:
        return None
    return HfRef(org=match.group(1), repo=match.group(2), revision=match.group(3))


def validate_hf_source(source: str | None, allowlist: tuple[str, ...] = ()) -> list[ScanFinding]:
    """ART-HF-01 (unpinned / malformed) and ART-HF-02 (repo not allowlisted). Non-`hf:` sources give no findings."""
    if source is None or not source.startswith("hf:"):
        return []
    ref = parse_hf_source(source)
    if ref is None:
        return [
            make_finding(
                "ART-HF-01",
                Severity.high,
                "Malformed Hugging Face source: expected hf:<org>/<repo>@<40-hex commit sha>.",
                detail=f"source: {sanitize(source, 160)}",
            )
        ]
    findings: list[ScanFinding] = []
    if not ref.pinned:
        findings.append(
            make_finding(
                "ART-HF-01",
                Severity.high,
                "Hugging Face source is not pinned to a 40-hex commit SHA (branches and tags can move; "
                "pin by revision to defend against namespace reuse).",
                detail=f"repo {sanitize(ref.repo_id, 160)} revision {sanitize(ref.revision, 60)}",
            )
        )
    if not any(fnmatch.fnmatchcase(ref.repo_id, pattern) for pattern in allowlist):
        findings.append(
            make_finding(
                "ART-HF-02",
                Severity.high,
                "Hugging Face repository is not on the policy allowlist.",
                detail=f"repo {sanitize(ref.repo_id, 160)}",
            )
        )
    return findings
