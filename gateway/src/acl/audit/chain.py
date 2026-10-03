"""Hash-chained append-only JSONL audit log (contract: `acl.contracts.canonical.audit_record_hash`).

    hash = sha256(prev_hash + "\\n" + canonical_json(record without "hash")), genesis prev_hash = "0"*64,
    seq starts at 0. Each line is the canonical JSON of the full record (hash included).

`AuditChain` is the single writer (an `asyncio.Lock` serialises appends) and resumes from the last line
on startup. `verify_chain` re-computes the whole chain and reports the first bad record: an edited line
(hash mismatch), a deleted/reordered line (seq or prev_hash mismatch). Truncation of the tail is not
detectable from the file alone; the admin endpoint compares the head against the DB index for that.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acl.contracts.admin import ChainVerifyResult
from acl.contracts.audit import GENESIS_HASH, AuditEvent
from acl.contracts.canonical import audit_record_hash, canonical_json

log = logging.getLogger(__name__)


def _last_line(path: Path) -> str | None:
    """Last non-empty line of the file (reads a bounded tail)."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        chunk = 8192
        data = b""
        while size > 0:
            read = min(chunk, size)
            size -= read
            f.seek(size)
            data = f.read(read) + data
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            if len(lines) >= 2 or size == 0:
                return lines[-1].decode("utf-8", "replace") if lines else None
            chunk *= 2
    return None


class AuditChain:
    """Appends records to the JSONL file. `seq`/`prev_hash`/`hash` are assigned under the lock."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()
        self._seq = 0
        self._prev = GENESIS_HASH
        self._needs_newline = False
        self.resumed = False

    @property
    def lock(self) -> asyncio.Lock:
        return self._lock

    @property
    def head(self) -> tuple[int | None, str]:
        return (self._seq - 1 if self._seq else None, self._prev)

    def resume(self) -> None:
        """Continue the chain from the last parseable line (call once, before the first append)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        with self.path.open("rb") as f:
            f.seek(-1, 2)
            self._needs_newline = f.read(1) != b"\n"  # torn tail: never glue a record onto it
        candidates: list[bytes] = []
        tail = _last_line(self.path)
        if tail is not None:
            candidates.append(tail.encode("utf-8"))
        for attempt in range(2):
            for raw in candidates:
                try:
                    rec = json.loads(raw)
                    self._seq, self._prev = int(rec["seq"]) + 1, str(rec["hash"])
                    self.resumed = True
                    return
                except (ValueError, KeyError, TypeError):
                    log.error("audit log: unparseable trailing line ignored while resuming (verify will report it)")
            if attempt == 0:  # walk back through the whole file for the last parseable record
                with self.path.open("rb") as f:
                    candidates = [ln for ln in reversed(f.read().split(b"\n")) if ln.strip()]

    def append_locked(self, event: AuditEvent) -> AuditEvent:
        """Assign seq/prev_hash/hash and write the line. The caller MUST hold `lock`."""
        draft = event.model_dump(mode="json")
        draft["seq"] = self._seq
        draft["prev_hash"] = self._prev
        draft["hash"] = GENESIS_HASH  # placeholder, replaced below (excluded from the hash)
        digest = audit_record_hash(self._prev, draft)
        draft["hash"] = digest
        final = AuditEvent.model_validate(draft)
        line = canonical_json(draft) + "\n"
        with self.path.open("ab") as f:
            if self._needs_newline:
                f.write(b"\n")
                self._needs_newline = False
            f.write(line.encode("utf-8"))
            f.flush()
        self._seq += 1
        self._prev = digest
        return final


def iter_lines(path: Path, upto_bytes: int | None = None) -> Iterator[tuple[int, bytes]]:
    """(1-based line number, raw line) for every non-empty line, optionally only the first `upto_bytes`."""
    with path.open("rb") as f:
        data = f.read() if upto_bytes is None else f.read(upto_bytes)
    for n, raw in enumerate(data.split(b"\n"), start=1):
        if raw.strip():
            yield n, raw


def _bad(seq: int, lineno: int, count: int, head_seq: int | None, prev: str, msg: str) -> ChainVerifyResult:
    return ChainVerifyResult(
        ok=False,
        records=count,
        head_seq=head_seq,
        head_hash=prev if count else None,
        first_bad_seq=seq,
        message=f"line {lineno} (seq {seq}): {msg}",
    )


def verify_chain(path: Path, *, upto_bytes: int | None = None) -> ChainVerifyResult:
    path = Path(path)
    if not path.exists():
        return ChainVerifyResult(ok=True, records=0, message="no audit log yet")
    prev, expected, count = GENESIS_HASH, 0, 0
    head_seq: int | None = None
    for lineno, raw in iter_lines(path, upto_bytes):
        try:
            rec: dict[str, Any] = json.loads(raw)
            seq = int(rec["seq"])
            claimed = str(rec["hash"])
        except (ValueError, KeyError, TypeError):
            return ChainVerifyResult(
                ok=False,
                records=count,
                head_seq=head_seq,
                head_hash=prev if count else None,
                first_bad_seq=expected,
                message=f"line {lineno} is not a valid audit record",
            )

        if seq != expected:
            kind = "record deleted or reordered" if seq > expected else "record duplicated or reordered"
            return _bad(seq, lineno, count, head_seq, prev, f"expected seq {expected}, found {seq}; {kind}")
        if rec.get("prev_hash") != prev:
            return _bad(
                seq,
                lineno,
                count,
                head_seq,
                prev,
                "prev_hash does not match the previous record (deleted/inserted/reordered)",
            )
        if audit_record_hash(prev, rec) != claimed:
            return _bad(seq, lineno, count, head_seq, prev, "hash mismatch; record content was modified")
        prev, expected, count, head_seq = claimed, expected + 1, count + 1, seq
    return ChainVerifyResult(
        ok=True,
        records=count,
        head_seq=head_seq,
        head_hash=prev if count else None,
        message="chain verified" if count else "audit log is empty",
    )


def read_records(
    path: Path, since: datetime | None = None, until: datetime | None = None
) -> Iterator[tuple[dict[str, Any], bytes]]:
    """Parsed records with their raw lines, filtered by timestamp (UTC)."""
    if not Path(path).exists():
        return
    for _, raw in iter_lines(Path(path)):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if since is not None or until is not None:
            ts = datetime.fromisoformat(str(rec.get("timestamp", "")).replace("Z", "+00:00"))
            ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
        yield rec, raw
