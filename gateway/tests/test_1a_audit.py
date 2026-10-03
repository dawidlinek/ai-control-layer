"""1A: hash-chained audit log, DB index, incidents, SSE fan-out, exports, metrics, migration."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import jsonschema
import pytest

from acl.audit.builder import build_event, redacted_text
from acl.audit.chain import AuditChain, verify_chain
from acl.audit.export import iter_export, to_ocsf
from acl.audit.incidents import record_incident
from acl.audit.metrics import GatewayMetrics
from acl.audit.service import AuditService
from acl.audit.stream import EventStreamHub
from acl.contracts.audit import GENESIS_HASH, AuditEvent, EventType
from acl.contracts.canonical import audit_record_hash
from acl.contracts.common import Action, CostTier, Phase, Severity, Versions
from acl.contracts.decision import Finding, Verdict
from acl.db import create_all, make_engine, make_sessionmaker
from acl.engine.decide import compose_decision
from acl.policy.models import GlobalSettings
from acl.testing import make_context, make_principal

REPO = Path(__file__).resolve().parents[2]
EVENT_SCHEMA = json.loads((REPO / "contracts" / "event.schema.json").read_text(encoding="utf-8"))
RAW_PESEL = "44051401359"


def decision_for(ctx, *verdicts: Verdict):  # type: ignore[no-untyped-def]
    return compose_decision(ctx, list(verdicts), GlobalSettings())


def pii_verdict(field: str = "messages[0].content", start: int = 6, end: int = 17) -> Verdict:
    return Verdict(
        control_id="SEC-PII-01",
        control_type="pii",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.pseudonymise,
        rule_ids=["SEC-PII-01"],
        data_class="confidential",  # type: ignore[arg-type]
        findings=[
            Finding(
                entity_type="PESEL", field=field, start=start, end=end, replacement="<PESEL_1>", value_hash="ab" * 8
            )
        ],
    )


@pytest.fixture
async def service(tmp_path: Path):  # type: ignore[no-untyped-def]
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
    await create_all(engine)
    sessions = make_sessionmaker(engine)
    chain = AuditChain(tmp_path / "logs" / "audit.jsonl")
    chain.resume()
    hub = EventStreamHub()
    svc = AuditService(
        chain=chain,
        sessions=sessions,
        salt="salt",
        stream=hub,
        metrics=GatewayMetrics(),
        versions=lambda: Versions(policy="v-test"),
    )
    yield svc
    await engine.dispose()


def lines(svc: AuditService) -> list[str]:
    return svc.chain.path.read_text(encoding="utf-8").splitlines()


async def fill(svc: AuditService, n: int = 5) -> None:
    for i in range(n):
        ctx = make_context(f"message {i}")
        await svc.record_decision(ctx, decision_for(ctx))


# ------------------------------------------------------------------ chain


async def test_chain_is_valid_and_matches_the_contract(service: AuditService) -> None:
    await fill(service, 4)
    recs = [json.loads(x) for x in lines(service)]
    assert [r["seq"] for r in recs] == [0, 1, 2, 3]
    assert recs[0]["prev_hash"] == GENESIS_HASH
    for prev, cur in pairwise(recs):
        assert cur["prev_hash"] == prev["hash"]
    for r in recs:
        assert audit_record_hash(r["prev_hash"], r) == r["hash"]  # the contract's own function
        jsonschema.validate(r, EVENT_SCHEMA)
        AuditEvent.model_validate(r)
    result = verify_chain(service.chain.path)
    assert result.ok and result.records == 4 and result.head_seq == 3 and result.head_hash == recs[-1]["hash"]


async def test_tampered_line_is_detected(service: AuditService) -> None:
    await fill(service, 5)
    ls = lines(service)
    rec = json.loads(ls[2])
    rec["severity"] = "critical"  # edit without re-hashing
    ls[2] = json.dumps(rec)
    service.chain.path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    res = verify_chain(service.chain.path)
    assert not res.ok and res.first_bad_seq == 2 and "modified" in res.message


async def test_rehashed_edit_breaks_the_next_link(service: AuditService) -> None:
    await fill(service, 5)
    ls = lines(service)
    rec = json.loads(ls[2])
    rec["severity"] = "critical"
    rec["hash"] = audit_record_hash(rec["prev_hash"], rec)  # a clever editor re-hashes the edited record...
    ls[2] = json.dumps(rec)
    service.chain.path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    res = verify_chain(service.chain.path)
    assert not res.ok and res.first_bad_seq == 3  # ...but record 3 no longer chains to it


async def test_deleted_line_is_detected(service: AuditService) -> None:
    await fill(service, 5)
    ls = lines(service)
    del ls[2]
    service.chain.path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    res = verify_chain(service.chain.path)
    assert not res.ok and res.first_bad_seq == 3 and "deleted" in res.message


async def test_reordered_lines_are_detected(service: AuditService) -> None:
    await fill(service, 5)
    ls = lines(service)
    ls[1], ls[2] = ls[2], ls[1]
    service.chain.path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    res = verify_chain(service.chain.path)
    assert not res.ok and res.first_bad_seq == 2


async def test_deleted_first_line_and_garbage_line(service: AuditService) -> None:
    await fill(service, 3)
    ls = lines(service)
    service.chain.path.write_text("\n".join(ls[1:]) + "\n", encoding="utf-8")
    assert not verify_chain(service.chain.path).ok
    service.chain.path.write_text("\n".join([ls[0], "not json", ls[1]]) + "\n", encoding="utf-8")
    res = verify_chain(service.chain.path)
    assert not res.ok and "not a valid audit record" in res.message


async def test_resume_after_restart_continues_the_chain(service: AuditService, tmp_path: Path) -> None:
    await fill(service, 3)
    head_hash = json.loads(lines(service)[-1])["hash"]
    service.chain.close()  # the old process is gone: it released the single-writer lock
    restarted = AuditChain(service.chain.path)
    restarted.resume()
    assert restarted.resumed and restarted.head == (2, head_hash)
    service.chain = restarted
    await fill(service, 2)
    recs = [json.loads(x) for x in lines(service)]
    assert [r["seq"] for r in recs] == [0, 1, 2, 3, 4] and recs[3]["prev_hash"] == head_hash
    assert verify_chain(service.chain.path).ok


async def test_resume_survives_a_torn_tail(service: AuditService) -> None:
    await fill(service, 3)
    with service.chain.path.open("ab") as f:
        f.write(b'{"seq": 3, "hash": "trunc')  # crash mid-write: partial line, no newline
    service.chain.close()
    chain = AuditChain(service.chain.path)
    chain.resume()
    assert chain.head[0] == 2  # continues from the last intact record
    service.chain = chain
    await fill(service, 1)
    res = verify_chain(service.chain.path)
    assert not res.ok and "not a valid audit record" in res.message  # the torn line is reported, never hidden


def test_empty_and_missing_logs(tmp_path: Path) -> None:
    assert verify_chain(tmp_path / "none.jsonl").ok
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    res = verify_chain(p)
    assert res.ok and res.records == 0 and res.head_seq is None
    chain = AuditChain(p)
    chain.resume()
    assert chain.head == (None, GENESIS_HASH)


async def test_concurrent_writers_stay_ordered(service: AuditService) -> None:
    async def one(i: int) -> None:
        ctx = make_context(f"c{i}")
        await service.record_decision(ctx, decision_for(ctx))

    await asyncio.gather(*(one(i) for i in range(40)))
    res = verify_chain(service.chain.path)
    assert res.ok and res.records == 40


# ------------------------------------------------------------------ records never hold raw values


async def test_no_raw_values_in_records_and_findings_are_reduced(service: AuditService) -> None:
    ctx = make_context(f"PESEL {RAW_PESEL} ok")
    d = decision_for(ctx, pii_verdict())
    event = await service.record_decision(ctx, d, redacted_payload=redacted_text(ctx, d.verdicts))
    raw = service.chain.path.read_text(encoding="utf-8")
    assert RAW_PESEL not in raw
    assert event.redacted_payload == "PESEL <PESEL_1> ok"
    f = event.verdicts[0].findings[0]
    assert (f.entity_type, f.field, f.start, f.end, f.value_hash) == ("PESEL", "messages[0].content", 6, 17, "ab" * 8)
    assert not hasattr(f, "replacement") and event.payload_hash and len(event.payload_hash) == 64
    assert (
        event.severity == Severity.low
        and event.decision is not None
        and event.decision.applied == [Action.pseudonymise]
    )


def test_redacted_text_masks_unreplaced_and_overlapping_spans() -> None:
    ctx = make_context("abcdefghij secret tail")
    v = Verdict(
        control_id="SEC-X-01",
        control_type="x",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        findings=[
            Finding(entity_type="A", field="messages[0].content", start=0, end=6),  # no replacement → generic mask
            Finding(entity_type="B", field="messages[0].content", start=4, end=10, replacement="<B>"),  # overlaps A
        ],
    )
    out = redacted_text(ctx, [v])
    assert out == "[REDACTED:A] secret tail"  # union masked; no fragment of the overlapped span survives
    for leaked in ("abcd", "ghij", "ef"):
        assert leaked not in out


def test_build_event_for_tool_call_hashes_arguments() -> None:
    ctx = make_context(
        {"tool": "mail.send", "arguments": {"to": "x@evil.tld"}},
        point="tool_call",  # type: ignore[arg-type]
    )
    event = build_event(ctx, decision_for(ctx), salt="s")
    assert event.tool == "mail.send" and event.args_hash and "evil" not in event.model_dump_json()


# ------------------------------------------------------------------ index, incidents, SSE, metrics


async def test_events_land_in_the_index_and_stream(service: AuditService) -> None:
    from acl.audit import queries

    sub = service.stream.subscribe()
    ctx = make_context(f"PESEL {RAW_PESEL}", principal=make_principal("jan", ["credit-analysts"]))
    d = decision_for(ctx, pii_verdict())
    await service.record_decision(ctx, d)
    await service.record_event(EventType.policy_change, detail={"version": "v2"})
    summary = await asyncio.wait_for(sub.get(), 1)
    assert summary.action == Action.pseudonymise and summary.username == "jan" and summary.groups == ["credit-analysts"]
    rows = await queries.list_events(service.sessions, group="credit-analysts")
    assert len(rows) == 1 and rows[0].rule_ids == ["SEC-PII-01"]
    assert len(await queries.list_events(service.sessions, event_type="policy_change")) == 1
    assert len(await queries.list_events(service.sessions, control="SEC-PII-01", action="pseudonymise")) == 1
    full = await queries.get_event(service.sessions, rows[0].event_id)
    assert full is not None and full.hash == json.loads(lines(service)[0])["hash"]
    assert (await queries.head_of_index(service.sessions))[0] == 1  # type: ignore[index]
    sub.close()
    assert service.stream.subscribers == 0


async def test_sse_hub_fans_out_and_drops_oldest_for_slow_consumers() -> None:
    hub = EventStreamHub(maxsize=2)
    fast, slow = hub.subscribe(), hub.subscribe()
    from acl.contracts.admin import EventSummary

    def summary(i: int) -> EventSummary:
        return EventSummary(
            event_id=str(i), seq=i, timestamp=datetime.now(UTC), event_type="decision", severity=Severity.info
        )

    for i in range(4):
        await hub.publish(summary(i))
        if i % 2:
            assert (await fast.get()).seq == i - 1
            assert (await fast.get()).seq == i
    assert slow.queue.qsize() == 2 and slow.dropped == 2
    assert (await slow.get()).seq == 2  # newest two kept
    slow.close()
    assert hub.subscribers == 1


async def test_incident_grouping_by_category_subject_and_window(service: AuditService) -> None:
    from acl.audit import queries  # noqa: F401

    t0 = datetime.now(UTC)
    kw = {"title": "t", "severity": Severity.medium, "rule_ids": ["R-1"], "detail": {}}
    a = await record_incident(
        service.sessions, category="forbidden_model", subject="jan", event_ids=["e1"], now=t0, **kw
    )  # type: ignore[arg-type]
    b = await record_incident(
        service.sessions,
        category="forbidden_model",
        subject="jan",
        event_ids=["e2"],
        now=t0 + timedelta(minutes=9),
        **{**kw, "severity": Severity.high},  # type: ignore[arg-type]
    )
    assert a.id == b.id and b.event_ids == ["e1", "e2"] and b.severity == Severity.high
    other_subject = await record_incident(
        service.sessions, category="forbidden_model", subject="anna", event_ids=["e3"], now=t0, **kw
    )  # type: ignore[arg-type]
    other_category = await record_incident(
        service.sessions, category="exfiltration_attempt", subject="jan", event_ids=["e4"], now=t0, **kw
    )  # type: ignore[arg-type]
    late = await record_incident(
        service.sessions,
        category="forbidden_model",
        subject="jan",
        event_ids=["e5"],
        now=t0 + timedelta(minutes=9 + 11),
        **kw,  # type: ignore[arg-type]
    )
    assert (
        len({a.id, other_subject.id, other_category.id, late.id}) == 4
    )  # >10 min after the last update → new incident


async def test_record_event_incident_with_category_opens_incident(service: AuditService) -> None:
    from sqlalchemy import select

    from acl.audit.db_models import IncidentRow

    p = make_principal("jan")
    await service.record_event(
        EventType.incident,
        severity=Severity.high,
        detail={"category": "mcp_rug_pull", "title": "Tool description changed", "rule_ids": ["SEC-MCP-01"]},
        principal=p,
    )
    await service.record_event(
        EventType.incident, detail={"incident_id": "x", "change": {}}, principal=p
    )  # no category
    async with service.sessions() as s:
        rows = (await s.execute(select(IncidentRow))).scalars().all()
    assert len(rows) == 1 and rows[0].category == "mcp_rug_pull" and rows[0].rule_ids == ["SEC-MCP-01"]


async def test_metrics_are_recorded(service: AuditService) -> None:
    ctx = make_context(f"PESEL {RAW_PESEL}")
    await service.record_decision(ctx, decision_for(ctx, pii_verdict()))
    text = service.metrics.render().decode()
    assert 'acl_decisions_total{action="pseudonymise",point="ingress"} 1.0' in text
    assert 'acl_control_latency_seconds_count{control="SEC-PII-01"} 1.0' in text
    assert "acl_audit_chain_head_seq 0.0" in text


# ------------------------------------------------------------------ exports


async def test_export_formats(service: AuditService) -> None:
    ctx = make_context(f"PESEL {RAW_PESEL}")
    await service.record_decision(ctx, decision_for(ctx, pii_verdict()))
    blocked = make_context("x", principal=make_principal("=cmd|calc"))
    block = Verdict(
        control_id="SEC-SECRET-01",
        control_type="secrets",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.block,
        final=True,
        rule_ids=["SEC-SECRET-01"],
        reason="secret",
    )
    await service.record_decision(blocked, decision_for(blocked, block))
    path = service.chain.path
    assert b"".join(iter_export(path, "jsonl")).decode() == path.read_text(encoding="utf-8")
    ocsf = [json.loads(x) for x in b"".join(iter_export(path, "ocsf")).decode().splitlines()]
    assert [o["disposition_id"] for o in ocsf] == [11, 2]
    assert ocsf[1]["severity_id"] == 4 and ocsf[1]["finding_info"]["types"] == ["SEC-SECRET-01"]
    assert ocsf[1]["actor"]["user"]["name"] == "=cmd|calc" and ocsf[0]["metadata"]["sequence"] == 0
    csv_text = b"".join(iter_export(path, "csv")).decode()
    assert "'=cmd|calc" in csv_text  # formula injection neutralised
    assert len(csv_text.splitlines()) == 3
    assert b"".join(iter_export(path, "jsonl", since=datetime.now(UTC) + timedelta(days=1))) == b""
    assert to_ocsf(json.loads(lines(service)[0]))["class_uid"] == 2004


# ------------------------------------------------------------------ migration


def test_alembic_migration_matches_models(tmp_path: Path) -> None:
    import sqlalchemy as sa

    from acl.migrate import upgrade_head

    url = f"sqlite+aiosqlite:///{tmp_path / 'm.db'}"
    upgrade_head(url)
    insp = sa.inspect(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))
    from acl.audit.db_models import AuditEventRow, IncidentRow

    for model in (AuditEventRow, IncidentRow):
        migrated = {c["name"] for c in insp.get_columns(model.__tablename__)}
        assert migrated == {c.name for c in model.__table__.columns}, model.__tablename__
