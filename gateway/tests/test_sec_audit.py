"""CP1 security fixes: audit writer robustness (surrogates, torn writes, single writer)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from acl.audit.chain import AuditChain, AuditLogLocked, verify_chain
from acl.contracts.audit import GENESIS_HASH, AuditEvent, EventType
from acl.contracts.common import Versions


def _event(**detail: object) -> AuditEvent:
    return AuditEvent(
        event_id="e",
        seq=0,
        timestamp=datetime(2026, 10, 3, tzinfo=UTC),
        event_type=EventType.system_alert,
        versions=Versions(policy="t"),
        detail=dict(detail),
        model_requested=str(detail.get("model", "")) or None,
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )


def test_lone_surrogate_is_scrubbed_and_recorded(tmp_path: Path) -> None:
    chain = AuditChain(tmp_path / "a.jsonl")
    chain.resume()
    rec = chain.append_locked(_event(model="smart\ud800"))
    assert rec.model_requested == "smart\ufffd"
    assert verify_chain(tmp_path / "a.jsonl").ok
    chain.close()


def test_failed_write_never_glues_next_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "a.jsonl"
    chain = AuditChain(path)
    chain.resume()
    chain.append_locked(_event())
    path.write_bytes(path.read_bytes() + b'{"torn":')  # simulate a crash mid-write
    chain._needs_newline = False
    real_open = Path.open

    def failing_open(self: Path, *a, **k):  # type: ignore[no-untyped-def]
        if self == path and a and a[0] == "ab":
            raise OSError("disk full")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(OSError):
        chain.append_locked(_event())
    monkeypatch.setattr(Path, "open", real_open)
    chain.append_locked(_event())
    lines = path.read_bytes().split(b"\n")
    assert lines[1] == b'{"torn":'  # torn line stays on its own line
    chain.close()


def test_second_writer_is_refused(tmp_path: Path) -> None:
    a = AuditChain(tmp_path / "a.jsonl")
    a.resume()
    b = AuditChain(tmp_path / "a.jsonl")
    with pytest.raises(AuditLogLocked):
        b.resume()
    a.close()
    b.resume()  # free again after the first writer closed
    b.close()
