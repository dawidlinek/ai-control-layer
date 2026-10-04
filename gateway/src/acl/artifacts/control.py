"""SEC-ART-01: model-artifact scanner as an inspection control (point `artifact_load`).

Runs in the `normalise` phase so that the pickle globals it finds are in `ctx.attributes["pickle_globals"]`
before SEC-SIG-01 (deterministic phase) matches feed `opcode` entries against them. Default deny: anything
other than a `safe` scan verdict blocks, and the block is final. Params are the scanner policy knobs; an admin
grants an exception for a blocked format by adding `{sha256, reason, formats, expires}` to `exceptions`.

The verdict carries rule ids and entity types only (never file content); the full report is returned in
`outputs["artifact_scan"]` (always, also on allow) for the admin API, which stores it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from acl.artifacts.report import FormatException, ScanPolicy, ScanReport, severity_rank
from acl.artifacts.scanner import scan_file
from acl.contracts.common import Action, InspectionPoint, Phase, Severity, Taxonomy
from acl.contracts.decision import Finding, Verdict
from acl.contracts.feed import SignatureType
from acl.contracts.inspection import ArtifactPayload, InspectionContext
from acl.controls.base import Control, ControlDeps, register_control
from acl.feed.compile import compile_entries
from acl.policy.models import ControlConfig

log = logging.getLogger(__name__)

_SEVERITY_SCORE = {
    Severity.info: 0.1,
    Severity.low: 0.3,
    Severity.medium: 0.5,
    Severity.high: 0.8,
    Severity.critical: 1.0,
}
_MAX_RULE_IDS = 25
MAX_FILE_BYTES_DEFAULT = 8 * 1024**3


class ArtifactException(BaseModel):
    """Policy-granted exception for a blocked format, matched by the file's sha256."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    reason: str = Field(min_length=3, max_length=300)
    formats: list[str] = Field(default_factory=list, description="Empty = any format.")
    expires: date | None = None


class ArtifactScanParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_formats: list[str] = Field(default_factory=lambda: ["safetensors", "gguf"])
    exceptions: list[ArtifactException] = Field(default_factory=list)
    hf_repo_allowlist: list[str] = Field(default_factory=list)
    max_file_bytes: int = Field(default=MAX_FILE_BYTES_DEFAULT, ge=1)
    max_pickle_bytes: int = Field(default=256 * 1024**2, ge=1)
    min_torch_version: str = "2.6.0"
    use_feed_opcodes: bool = True


def _worst(report: ScanReport) -> Severity:
    return max((f.severity for f in report.findings), key=severity_rank, default=Severity.high)


@register_control
class ArtifactScanControl(Control):
    type = "artifact_scan"
    phase = Phase.normalise
    Params = ArtifactScanParams
    cacheable = False  # reads a file and the live signature bundle

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        policy = deps.get("policy")
        local = list(policy.signatures.local_rules) if policy is not None else []  # type: ignore[attr-defined]
        compiled, _errors = compile_entries(local)
        self._local_opcodes = [e for e in compiled if e.entry.type == SignatureType.opcode]

    # ------------------------------------------------------------------ policy

    def feed_opcode_globs(self) -> tuple[tuple[str, str], ...]:
        """(signature id, glob) of live `opcode` entries for artifact_load: local rules plus the active bundle."""
        p: ArtifactScanParams = self.params  # type: ignore[assignment]
        if not p.use_feed_opcodes:
            return ()
        now = time.time()
        merged = {e.id: e for e in self._local_opcodes}
        store = self.deps.get("signatures")
        bundle = store.current() if store is not None else None
        if bundle is not None:
            merged.update({e.id: e for e in bundle.entries if e.entry.type == SignatureType.opcode})
        out: list[tuple[str, str]] = []
        for entry in merged.values():
            if InspectionPoint.artifact_load in entry.stages and entry.live(now):
                out.extend((entry.id, glob) for glob in entry.opcode_globs)
        return tuple(out)

    def scan_policy(self) -> ScanPolicy:
        p: ArtifactScanParams = self.params  # type: ignore[assignment]
        return ScanPolicy(
            allowed_formats=tuple(p.allowed_formats),
            exceptions=tuple(
                FormatException(sha256=e.sha256.lower(), reason=e.reason, formats=tuple(e.formats), expires=e.expires)
                for e in p.exceptions
            ),
            hf_repo_allowlist=tuple(p.hf_repo_allowlist),
            opcode_globs=self.feed_opcode_globs(),
            max_file_bytes=p.max_file_bytes,
            max_pickle_bytes=p.max_pickle_bytes,
            min_torch_version=p.min_torch_version,
        )

    # ------------------------------------------------------------------ inspect

    def _unavailable(self, why: str) -> Verdict:
        return self.verdict(
            action=Action.block,
            final=True,
            rule_ids=[self.id],
            findings=[Finding(entity_type="FILE_UNAVAILABLE", field="artifact", score=1.0, rule_id=self.id)],
            score=1.0,
            reason=f"artifact file unavailable: {why}; failing closed",
            taxonomy=self._taxonomy([]),
        )

    def _taxonomy(self, cves: list[str]) -> Taxonomy:
        tax = Taxonomy(**self.config.taxonomy.model_dump())
        for tag, bucket in (("LLM03:2025", tax.owasp_llm), ("AML.T0010", tax.atlas)):
            if tag not in bucket:
                bucket.append(tag)
        for cve in cves:
            if cve not in tax.cve:
                tax.cve.append(cve)
        return tax

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        payload = ctx.payload
        if not isinstance(payload, ArtifactPayload):
            return self.verdict()
        if not payload.local_path:
            return self._unavailable("no local path")
        path = Path(payload.local_path)
        if not await asyncio.to_thread(path.is_file):
            return self._unavailable("file not found")
        scan_policy = self.scan_policy()
        try:
            report: ScanReport = await asyncio.to_thread(
                scan_file,
                path,
                filename=payload.filename,
                policy=scan_policy,
                expected_sha256=payload.sha256,
                source=payload.source,
            )
        except OSError:
            return self._unavailable("file unreadable")

        outputs = {"pickle_globals": list(report.pickle_globals), "artifact_scan": report.to_dict()}
        if report.verdict == "safe":
            return self.verdict(outputs=outputs)

        findings = sorted(report.findings, key=lambda f: (not f.malicious, -severity_rank(f.severity), f.rule_id))
        rule_ids = [self.id, *dict.fromkeys(sorted({f.rule_id for f in report.findings}))][:_MAX_RULE_IDS]
        worst = _worst(report)
        top = findings[0] if findings else None
        what = ""
        if top is not None:
            what = f"{top.rule_id}" + (f" ({top.detail[:100]})" if top.detail else "")
        cves = [c for f in report.findings for c in f.cve]
        return self.verdict(
            action=Action.block,
            final=True,
            rule_ids=rule_ids,
            findings=[
                Finding(
                    entity_type=f.rule_id,
                    field="artifact",
                    score=_SEVERITY_SCORE[f.severity],
                    rule_id=f.rule_id,
                )
                for f in findings[:_MAX_RULE_IDS]
            ],
            score=_SEVERITY_SCORE[worst],
            reason=f"artifact verdict {report.verdict}: {what}",
            taxonomy=self._taxonomy(cves),
            outputs=outputs,
        )
