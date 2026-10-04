"""Admin: model-artifact scanner (4A).

`POST /artifacts/scan` streams an upload to a temp file, evaluates it at the `artifact_load` inspection point
(SEC-ART-01, then SEC-SIG-01 feed opcode signatures), stores the result and audits it. The temp file is always
removed. `GET /artifacts` and `GET /artifacts/{scan_id}` read the stored results.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile

from acl.api.deps import ERROR_RESPONSES, Admin, Viewer
from acl.artifacts.control import MAX_FILE_BYTES_DEFAULT
from acl.artifacts.report import severity_rank
from acl.artifacts.store import ArtifactStore, new_scan_id
from acl.contracts.admin import ArtifactFinding, ArtifactScanResult
from acl.contracts.audit import EventType
from acl.contracts.common import InspectionPoint, Severity
from acl.contracts.inspection import ArtifactPayload
from acl.engine.actions import GatewayUnavailable, evaluate_point

log = logging.getLogger(__name__)

router = APIRouter(responses=ERROR_RESPONSES)

CHUNK = 1024 * 1024
MAX_FILENAME = 200
_SEVERITY = {"malicious": Severity.critical, "blocked_format": Severity.high, "suspicious": Severity.high}


def _store(request: Request) -> ArtifactStore:
    store = getattr(request.app.state, "artifacts", None)
    if store is None:
        raise HTTPException(503, detail="artifact store unavailable")
    return store


def safe_filename(raw: str | None) -> str:
    """Basename only (both separators), control characters removed, bounded; never empty."""
    name = PurePosixPath((raw or "").replace("\\", "/")).name
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    return name[:MAX_FILENAME] if name not in ("", ".", "..") else "upload.bin"


def _max_file_bytes(engine: Any) -> int:
    for control in engine.policy.controls:
        if control.type == "artifact_scan" and control.enabled:
            value = control.params.get("max_file_bytes")
            if isinstance(value, int) and value > 0:
                return value
    return MAX_FILE_BYTES_DEFAULT


def _findings(report: dict[str, Any]) -> list[ArtifactFinding]:
    return [
        ArtifactFinding(
            rule_id=f["rule_id"],
            severity=Severity(f["severity"]),
            message=f["message"],
            detail=f.get("detail"),
            cve=list(f.get("cve") or []),
        )
        for f in report.get("findings", [])
    ]


@router.post(
    "/artifacts/scan",
    response_model=ArtifactScanResult,
    tags=["artifacts"],
    operation_id="scanArtifact",
    responses={413: {"description": "File larger than the scanner limit"}, 503: {"description": "Scanner unavailable"}},
)
async def scan_artifact(
    request: Request, file: UploadFile, p: Admin, source: Annotated[str | None, Form()] = None
) -> ArtifactScanResult:
    app = request.app
    engine = getattr(app.state, "engine", None)
    store = _store(request)
    audit = getattr(app.state, "audit", None)
    if engine is None or audit is None:
        raise HTTPException(503, detail="policy or audit log unavailable")
    limit = _max_file_bytes(engine)
    filename = safe_filename(file.filename)
    ext = PurePosixPath(filename).suffix.lower().lstrip(".")

    fd, tmp = tempfile.mkstemp(prefix="acl-artifact-", suffix=".upload")
    tmp_path = Path(tmp)
    try:
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, detail=f"file exceeds the scanner limit of {limit} bytes")
                digest.update(chunk)
                await asyncio.to_thread(out.write, chunk)
        sha256 = digest.hexdigest()
        payload = ArtifactPayload(
            filename=filename,
            sha256=sha256,
            size=size,
            declared_format=ext or None,
            source=source or None,
            local_path=str(tmp_path),
        )
        try:
            ctx, decision = await evaluate_point(
                app, p, point=InspectionPoint.artifact_load, payload=payload, client_session=None, commit=False
            )
        except GatewayUnavailable as exc:
            raise HTTPException(503, detail=str(exc)) from exc
    finally:
        await asyncio.to_thread(tmp_path.unlink, missing_ok=True)

    report = ctx.attributes.get("artifact_scan")
    if report is None:  # control disabled, or it failed closed before producing a report
        verdict = "suspicious"
        findings = [
            ArtifactFinding(
                rule_id="ART-SCAN-00",
                severity=Severity.high,
                message="Scanner did not run or failed closed; the file was not verified.",
            )
        ]
        fmt, exception = "unknown", None
    else:
        verdict, findings = report["verdict"], _findings(report)
        fmt, exception = report["format_detected"], report.get("exception")

    # a block decided by another rule (feed signature, ...) means the content matched a known-bad signature
    foreign = [r for r in decision.rule_ids if r.startswith("SIG-")]
    if decision.action.value == "block" and foreign:
        verdict = "malicious"
        findings.extend(
            ArtifactFinding(
                rule_id=rule,
                severity=Severity.high,
                message=f"Blocked by signature {rule} from the signature feed.",
            )
            for rule in foreign
            if rule not in {f.rule_id for f in findings}
        )

    result = ArtifactScanResult(
        id=new_scan_id(),
        filename=filename,
        sha256=sha256,
        size=size,
        format_detected=fmt,
        verdict=verdict,  # type: ignore[arg-type]
        findings=findings,
        scanned_at=datetime.now(UTC),
        source=source or None,
        exception=exception,
        model_ids=[m.id for m in engine.policy.models if m.artifact is not None and m.artifact.sha256 == sha256],
        decision_id=decision.decision_id,
        scanned_by=p.username or p.subject,
    )
    await store.record(result)

    rule_ids = sorted({f.rule_id for f in findings})
    by_severity = sorted(findings, key=lambda f: -severity_rank(f.severity))
    headline = list(dict.fromkeys(f.rule_id for f in by_severity))[:3]
    event = await audit.record_event(
        EventType.artifact_scan,
        severity=_SEVERITY.get(verdict, Severity.info),
        detail={
            "scan_id": result.id,
            "filename": filename,
            "sha256": sha256,
            "format": fmt,
            "verdict": verdict,
            "rule_ids": rule_ids,
            "source": result.source,
        },
        principal=p,
        trace_id=decision.trace_id,
        session_id=ctx.session_id,
    )
    if verdict == "malicious":
        try:
            await audit.record_event(
                EventType.incident,
                severity=Severity.critical,
                detail={
                    "category": "artifact_blocked",
                    "title": f"Malicious model artifact {filename}: {', '.join(headline)}",
                    "rule_ids": rule_ids,
                    "related_event_ids": [event.event_id],
                    "scan_id": result.id,
                    "sha256": sha256,
                },
                principal=p,
                trace_id=decision.trace_id,
            )
        except Exception:  # the scan result is already stored and audited
            log.exception("artifact incident could not be recorded")
    return result


@router.get("/artifacts", response_model=list[ArtifactScanResult], tags=["artifacts"], operation_id="listArtifacts")
async def list_artifacts(request: Request, p: Viewer) -> list[ArtifactScanResult]:
    return await _store(request).list(limit=200)


@router.get(
    "/artifacts/{scan_id}",
    response_model=ArtifactScanResult,
    tags=["artifacts"],
    operation_id="getArtifact",
    responses={404: {"description": "Unknown scan id"}},
)
async def get_artifact(scan_id: str, request: Request, p: Viewer) -> ArtifactScanResult:
    result = await _store(request).get(scan_id)
    if result is None:
        raise HTTPException(404, detail="unknown artifact scan")
    return result
