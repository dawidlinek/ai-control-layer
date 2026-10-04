"""Model-artifact scanner: orchestrates format detection, the format walkers and the verdict.

Guarantees (see docs/CONCEPT.md section 9.2):

* nothing from the file is ever executed, imported or unpickled; walkers only parse structure;
* hostile input never raises: every parser failure becomes a finding (an unexpected internal error is
  reported as ART-INTERNAL-01 and fails closed as malicious);
* work is bounded (opcode count, member count, string lengths, header sizes) and files are read in a
  streaming way: the sha256 is computed in 1 MiB chunks, safetensors/GGUF only read their header;
* walkers always run, also for blocked formats, so a blocked `.pt` with `os.system` is `malicious`
  rather than merely `blocked_format`.

Verdict: any malicious finding -> `malicious`; else a format outside `allowed_formats` without a matching,
unexpired exception -> `blocked_format`; else any finding of severity >= medium -> `suspicious`; else `safe`.

Additional rule ids beyond the documented set: ART-SIZE-01 (file larger than `max_file_bytes`, suspicious) and
ART-INTERNAL-01 (unexpected scanner failure, malicious).
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import BinaryIO

from acl.artifacts.archives import looks_like_zip, scan_zip
from acl.artifacts.formats import (
    ARCHIVE_FORMATS,
    HEAD_BYTES,
    PICKLE_EXTENSIONS,
    PICKLE_FAMILY_EXTENSIONS,
    detect_magic,
    extension,
    npy_info,
)
from acl.artifacts.gguf import scan_gguf
from acl.artifacts.huggingface import validate_hf_source
from acl.artifacts.keras import scan_hdf5
from acl.artifacts.pickle_walk import PickleScan, scan_pickle, torch_note, torch_version_ok
from acl.artifacts.report import (
    FormatException,
    ScanFinding,
    ScanPolicy,
    ScanReport,
    Verdict,
    make_finding,
    sanitize,
    severity_rank,
)
from acl.artifacts.safetensors import scan_safetensors
from acl.contracts.common import Severity

__all__ = ["FormatException", "ScanPolicy", "ScanReport", "scan_bytes", "scan_file", "torch_version_ok"]

HASH_CHUNK = 1 << 20
PROBE_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 200
MODEL_FILE_EXTENSIONS = PICKLE_EXTENSIONS | {".keras", ".h5", ".hdf5"}
SEVEN_ZIP_HEADER_BYTES = 32


@dataclass(slots=True)
class _State:
    findings: list[ScanFinding] = field(default_factory=list)
    pickle_globals: list[str] = field(default_factory=list)
    format: str = "unknown"

    def add(self, finding: ScanFinding) -> None:
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(finding)

    def merge_pickle(self, walked: PickleScan) -> None:
        for finding in walked.findings:
            self.add(finding)
        for name in walked.globals:
            if name not in self.pickle_globals:
                self.pickle_globals.append(name)


def _clean_filename(name: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in name)
    return cleaned[:255]


def _hash_and_head(f: BinaryIO) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    total = 0
    head = b""
    f.seek(0)
    while True:
        chunk = f.read(HASH_CHUNK)
        if not chunk:
            break
        if len(head) < HEAD_BYTES:
            head += chunk[: HEAD_BYTES - len(head)]
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total, head


def _walk_pickle_stream(f: BinaryIO, size: int, policy: ScanPolicy, state: _State, *, start: int = 0) -> PickleScan:
    """Walk the pickle(s) stored in `f` from `start`, bounded by `max_pickle_bytes`."""
    cap = policy.max_pickle_bytes
    f.seek(start)
    data = f.read(min(max(size - start, 0), cap + 1))
    partial = len(data) > cap
    if partial:
        data = data[:cap]
        state.add(
            make_finding(
                "ART-PICKLE-05",
                Severity.high,
                "Pickle file exceeds the size limit; only its first bytes were walked.",
                detail=f"file size {size}, limit {cap}",
            )
        )
    walked = scan_pickle(data, opcode_globs=policy.opcode_globs, partial=partial)
    state.merge_pickle(walked)
    return walked


def _probe_pickle(f: BinaryIO, size: int, start: int = 0) -> bool:
    f.seek(start)
    head = f.read(min(max(size - start, 0), PROBE_BYTES))
    walked = scan_pickle(head, partial=size - start > PROBE_BYTES, probe=True)
    return walked.pickle_like()


def _scan_by_format(f: BinaryIO, size: int, head: bytes, ext: str, policy: ScanPolicy, state: _State) -> None:
    fmt = detect_magic(head, size)
    if fmt == "pickle_maybe":
        fmt = "pickle" if _probe_pickle(f, size) else "unknown"
    state.format = fmt

    if fmt == "safetensors":
        problems = scan_safetensors(f, size)
        for finding in problems:
            state.add(finding)
        if problems:
            if head[:1] == b"\x80" and len(head) > 1 and 2 <= head[1] <= 5:
                # Second opinion: a pickle disguised with a plausible length prefix.
                f.seek(0)
                if _probe_pickle(f, size):
                    _walk_pickle_stream(f, size, policy, state)
        elif looks_like_zip(f, size):
            state.add(_polyglot_finding(fmt))
    elif fmt == "gguf":
        for finding in scan_gguf(f, size):
            state.add(finding)
        if looks_like_zip(f, size):
            state.add(_polyglot_finding(fmt))
    elif fmt == "pickle":
        _walk_pickle_stream(f, size, policy, state)
    elif fmt == "zip":
        result = scan_zip(f, size, policy)
        state.format = result.format
        for finding in result.findings:
            state.add(finding)
        for name in result.pickle_globals:
            if name not in state.pickle_globals:
                state.pickle_globals.append(name)
    elif fmt == "hdf5":
        for finding in scan_hdf5(f, size):
            state.add(finding)
    elif fmt == "numpy":
        parsed = npy_info(head)
        if parsed is not None and parsed[1] and _probe_pickle(f, size, parsed[0]):
            _walk_pickle_stream(f, size, policy, state, start=parsed[0])
    elif fmt in ARCHIVE_FORMATS:
        if ext in PICKLE_FAMILY_EXTENSIONS:
            state.add(
                make_finding(
                    "ART-ARCHIVE-01",
                    Severity.critical,
                    f"File has the model extension {sanitize(ext, 20)} but is a {fmt} archive "
                    "(archive-format mismatch, nullifAI-style evasion).",
                    detail=f"detected {fmt}, expected a ZIP or raw pickle",
                    malicious=True,
                )
            )
        if fmt == "7z" and size > SEVEN_ZIP_HEADER_BYTES and _probe_pickle(f, size, SEVEN_ZIP_HEADER_BYTES):
            # Best effort: pickle bytes placed right after a 7z signature header are walked anyway.
            _walk_pickle_stream(f, size, policy, state, start=SEVEN_ZIP_HEADER_BYTES)
    elif ext in MODEL_FILE_EXTENSIONS:
        state.add(
            make_finding(
                "ART-FORMAT-02",
                Severity.high,
                f"File has the model extension {sanitize(ext, 20)} but its content is neither a pickle nor a "
                "known model container.",
                detail="unrecognised content",
                malicious=True,
            )
        )

    expected = {".safetensors": "safetensors", ".gguf": "gguf"}.get(ext)
    if expected is not None and state.format != expected and not _has_rule(state, "ART-FORMAT-02"):
        state.add(
            make_finding(
                "ART-FORMAT-02",
                Severity.high,
                f"Extension {ext} does not match the detected content format {state.format}.",
                detail=f"detected {state.format}",
                malicious=True,
            )
        )


def _has_rule(state: _State, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in state.findings)


def _polyglot_finding(fmt: str) -> ScanFinding:
    return make_finding(
        "ART-FORMAT-02",
        Severity.high,
        f"File is a valid {fmt} and also a valid ZIP archive (polyglot): another loader would read different data.",
        detail="valid ZIP end-of-central-directory found at the end of the file",
        malicious=True,
    )


def _matching_exception(policy: ScanPolicy, sha256: str, fmt: str, today: date) -> FormatException | None:
    for exc in policy.exceptions:
        if exc.sha256.strip().lower() != sha256:
            continue
        if exc.formats and fmt not in exc.formats:
            continue
        if exc.expires is not None and exc.expires < today:
            continue
        return exc
    return None


def _scan_stream(
    f: BinaryIO,
    filename: str,
    policy: ScanPolicy,
    expected_sha256: str | None,
    source: str | None,
    today: date | None,
) -> ScanReport:
    today = today or date.today()
    state = _State()
    sha256, size, head = _hash_and_head(f)
    ext = extension(filename)
    try:
        if expected_sha256 is not None and expected_sha256.strip().lower() != sha256:
            state.add(
                make_finding(
                    "ART-HASH-01",
                    Severity.critical,
                    "Declared sha256 does not match the file content.",
                    detail=f"declared {sanitize(expected_sha256.strip().lower(), 64)[:16]}..., "
                    f"computed {sha256[:16]}...",
                    malicious=True,
                )
            )
        for finding in validate_hf_source(source, policy.hf_repo_allowlist):
            state.add(finding)
        if size > policy.max_file_bytes:
            state.add(
                make_finding(
                    "ART-SIZE-01",
                    Severity.high,
                    "File exceeds the maximum scan size.",
                    detail=f"size {size}, limit {policy.max_file_bytes}",
                )
            )
        _scan_by_format(f, size, head, ext, policy, state)
    except Exception as exc:  # hostile input must never escape as an exception: fail closed
        state.add(
            make_finding(
                "ART-INTERNAL-01",
                Severity.high,
                "Scanner failed unexpectedly on this file; treated as malicious (fail closed).",
                detail=type(exc).__name__,
                malicious=True,
            )
        )

    fmt = state.format
    if fmt in ("torch_zip", "pickle"):
        state.add(torch_note(policy.min_torch_version))

    malicious = any(f.malicious for f in state.findings)
    blocked = fmt not in policy.allowed_formats
    exception = _matching_exception(policy, sha256, fmt, today) if blocked else None
    if blocked:
        if exception is not None:
            state.add(
                make_finding(
                    "ART-FORMAT-01",
                    Severity.info,
                    f"Blocked format {fmt} admitted by policy exception: {sanitize(exception.reason, 200)}.",
                    detail=f"sha256 {sha256[:16]}...",
                )
            )
        else:
            state.add(
                make_finding(
                    "ART-FORMAT-01",
                    Severity.high,
                    f"Format {fmt} is not allowed: only {', '.join(policy.allowed_formats) or 'nothing'} "
                    "may be loaded unless a policy exception is granted.",
                    detail=f"detected {fmt}",
                )
            )

    verdict: Verdict
    if malicious:
        verdict = "malicious"
    elif blocked and exception is None:
        verdict = "blocked_format"
    elif any(severity_rank(f.severity) >= severity_rank(Severity.medium) for f in state.findings):
        verdict = "suspicious"
    else:
        verdict = "safe"
    return ScanReport(
        filename=_clean_filename(filename),
        sha256=sha256,
        size=size,
        format_detected=fmt,
        verdict=verdict,
        findings=state.findings,
        pickle_globals=state.pickle_globals,
        exception=exception.reason if exception is not None and verdict != "malicious" else None,
    )


def scan_file(
    path: Path,
    *,
    filename: str | None = None,
    policy: ScanPolicy | None = None,
    expected_sha256: str | None = None,
    source: str | None = None,
    today: date | None = None,
) -> ScanReport:
    """Scan a model file on disk (streaming; the file is never executed or imported)."""
    path = Path(path)
    with path.open("rb") as handle:
        return _scan_stream(handle, filename or path.name, policy or ScanPolicy(), expected_sha256, source, today)


def scan_bytes(
    data: bytes,
    *,
    filename: str,
    policy: ScanPolicy | None = None,
    expected_sha256: str | None = None,
    source: str | None = None,
    today: date | None = None,
) -> ScanReport:
    """Scan in-memory bytes (tests / small payloads); writes nothing."""
    return _scan_stream(io.BytesIO(data), filename, policy or ScanPolicy(), expected_sha256, source, today)
