"""Signature feed bundle (concept §9.2).

Integrity: `signature.value` is computed over
    canonical_json(bundle without the "signature" key)
(canonical_json as in `acl.contracts.audit`). For `alg = sha256` the value is the hex digest
(checksum only: integrity, not authenticity). For `alg = ed25519` it is the base64 signature,
verified with the public key configured in policy (`signatures.feed.public_key`).
A bundle that fails verification, or whose `bundle_version` is not greater than the loaded one,
is rejected and the last good bundle stays active.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from .common import Action, InspectionPoint, Severity, StrictModel


class SignatureType(StrEnum):
    regex = "regex"
    yara = "yara"
    package_version = "package_version"
    url_path = "url_path"
    tool_desc_hash = "tool_desc_hash"
    manifest_hash = "manifest_hash"
    opcode = "opcode"
    arg_pattern = "arg_pattern"
    ioc_domain = "ioc_domain"


class SignatureEntry(StrictModel):
    id: str = Field(
        pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$",
        description="Rule id: `SIG-…` for curated signatures, e.g. `FEED-LOCAL-0001` for rules added in the panel.",
        examples=["SIG-PKG-LITELLM-01", "FEED-LOCAL-0001"],
    )
    type: SignatureType
    pattern: str = Field(
        description=(
            "regex/arg_pattern/url_path: RE2-compatible regex; yara: rule source; ioc_domain: domain "
            "(subdomains match); *_hash: sha256 hex; opcode: `module.attr` glob; package_version: "
            "`<ecosystem>:<name>` with versions in metadata.versions."
        )
    )
    severity: Severity = Severity.high
    action: Action = Action.block
    stages: list[InspectionPoint] = Field(
        default_factory=list, description="Where to match; empty = every stage applicable to the type."
    )
    description: str = ""
    atlas_technique: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    source: str = Field(default="internal", examples=["osv", "ghsa", "cisa-kev", "garak", "internal"])
    expires: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BundleSignature(StrictModel):
    alg: Literal["sha256", "ed25519"]
    key_id: str | None = None
    value: str


class FeedBundle(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    bundle_version: int = Field(ge=1)
    issued_at: datetime
    issuer: str = "acl-feed-server"
    entries: list[SignatureEntry]
    signature: BundleSignature
