"""Audit exports for SIEMs: JSONL (raw chain records), OCSF JSONL (Detection Finding), CSV."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acl import __version__
from acl.audit.chain import read_records

OCSF_VERSION = "1.3.0"
_SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
# OCSF `disposition_id`: 1 Allowed, 2 Blocked, 11 Corrected, 17 Logged, 99 Other
_DISPOSITION = {
    "allow": 1,
    "monitor": 17,
    "redact": 11,
    "pseudonymise": 11,
    "sanitize": 11,
    "route_local": 99,
    "downgrade": 99,
    "require_approval": 99,
    "block": 2,
}

CSV_COLUMNS = [
    "timestamp",
    "seq",
    "event_id",
    "event_type",
    "severity",
    "trace_id",
    "session_id",
    "subject",
    "username",
    "groups",
    "point",
    "model",
    "connector",
    "action",
    "would_action",
    "rule_ids",
    "risk_score",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "usd",
    "hash",
]


def _epoch_ms(ts: str) -> int:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int((dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp() * 1000)


def to_ocsf(rec: dict[str, Any]) -> dict[str, Any]:
    """Audit record → OCSF 1.3 Detection Finding (class 2004). Decisions carry the detection details."""
    dec = rec.get("decision") or {}
    principal = rec.get("principal") or {}
    action = dec.get("action")
    point = rec.get("point")
    taxonomy = rec.get("taxonomy") or {}
    title = f"{action or rec['event_type']}" + (f" at {point}" if point else "")
    finding: dict[str, Any] = {
        "uid": rec["event_id"],
        "title": title,
        "desc": dec.get("reason") or "",
        "types": list(dec.get("rule_ids") or []) or [rec["event_type"]],
        "analytic": {"name": dec.get("decided_by") or "acl-engine", "type_id": 1, "type": "Rule"},
        "related_events": [{"uid": rec["trace_id"], "type": "trace"}] if rec.get("trace_id") else [],
    }
    attacks = [{"technique": {"uid": t}} for t in taxonomy.get("atlas", [])]
    if attacks:
        finding["attacks"] = attacks
    out: dict[str, Any] = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": _SEVERITY_ID.get(rec.get("severity", "info"), 0),
        "severity": rec.get("severity", "info"),
        "status_id": 1,
        "time": _epoch_ms(rec["timestamp"]),
        "message": dec.get("reason") or title,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": rec["event_id"],
            "sequence": rec["seq"],
            "log_name": "acl-audit",
            "product": {"name": "AI Control Layer", "vendor_name": "ACL", "version": __version__},
        },
        "finding_info": finding,
        "disposition_id": _DISPOSITION.get(action, 0) if action else 0,
        "disposition": action or "unknown",
        "risk_score": round(float(dec.get("risk_score") or 0.0) * 100),
        "unmapped": {
            "acl": {
                "event_type": rec["event_type"],
                "applied": dec.get("applied", []),
                "would_action": dec.get("would_action"),
                "model": rec.get("model"),
                "connector": rec.get("connector"),
                "route": rec.get("route"),
                "usage": rec.get("usage"),
                "versions": rec.get("versions"),
                "taxonomy": taxonomy,
                "hash": rec.get("hash"),
            }
        },
    }
    if principal:
        out["actor"] = {
            "user": {
                "uid": principal.get("subject"),
                "name": principal.get("username"),
                "type": principal.get("kind"),
                "groups": [{"name": g} for g in principal.get("groups", [])],
            },
            "session": {"uid": rec.get("session_id")},
        }
    return out


def _safe_cell(v: Any) -> Any:
    """Neutralise spreadsheet formula injection from user-controlled strings."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def _csv_row(rec: dict[str, Any]) -> list[Any]:
    return [_safe_cell(v) for v in _csv_values(rec)]


def _csv_values(rec: dict[str, Any]) -> list[Any]:
    dec = rec.get("decision") or {}
    p = rec.get("principal") or {}
    u = rec.get("usage") or {}
    lat = rec.get("latency") or {}
    return [
        rec["timestamp"],
        rec["seq"],
        rec["event_id"],
        rec["event_type"],
        rec["severity"],
        rec.get("trace_id") or "",
        rec.get("session_id") or "",
        p.get("subject") or "",
        p.get("username") or "",
        ";".join(p.get("groups", [])),
        rec.get("point") or "",
        rec.get("model") or "",
        rec.get("connector") or "",
        dec.get("action") or "",
        dec.get("would_action") or "",
        ";".join(dec.get("rule_ids", [])),
        dec.get("risk_score", ""),
        lat.get("total_ms", ""),
        u.get("input_tokens", ""),
        u.get("output_tokens", ""),
        u.get("usd", ""),
        rec["hash"],
    ]


def iter_export(path: Path, fmt: str, since: datetime | None = None, until: datetime | None = None) -> Iterator[bytes]:
    """Stream the audit file in the requested format. `jsonl` yields the raw, verifiable lines."""
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        yield buf.getvalue().encode("utf-8")
    for rec, raw in read_records(path, since, until):
        if fmt == "jsonl":
            yield raw + b"\n"
        elif fmt == "ocsf":
            yield (json.dumps(to_ocsf(rec), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        else:
            buf = io.StringIO()
            csv.writer(buf).writerow(_csv_row(rec))
            yield buf.getvalue().encode("utf-8")
