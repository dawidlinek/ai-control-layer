"""Admin: approvals (2B), budgets (2D), models/connectors (1A/3B), MCP (2A), feed (1D),
artifacts (4A), insights (4B).

Each section is owned by the phase noted; the route signatures are the contract.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile

from acl.api.admin.paging import TOTAL_COUNT_RESPONSES, set_total
from acl.api.deps import ERROR_RESPONSES, Admin, Viewer, not_implemented
from acl.audit.queries import rule_hits, spend_by_connector, usage_by_model
from acl.contracts.admin import (
    ArtifactScanResult,
    ConnectorStatus,
    FeedRuleCreate,
    FeedRuleCreated,
    FeedSignature,
    FeedStatus,
    FeedTarget,
    InsightCluster,
    KillSwitchRequest,
    ModelInfo,
    PublishSkillRequest,
)
from acl.contracts.audit import EventType
from acl.contracts.common import Severity
from acl.feed.admin import FeedAdminClient, FeedAdminError, RuleInvalid, build_entry, describe
from acl.feed.compile import CompiledEntry, compile_entries, compile_entry
from acl.policy.models import Policy
from acl.routing.registry import RoutingTable

log = logging.getLogger(__name__)
router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- models & connectors (1A / 3B)


def _policy_and_table(request: Request) -> tuple[Policy, RoutingTable]:
    engine = request.app.state.engine
    if engine is None:
        raise HTTPException(503, detail="policy not loaded")
    return engine.policy, request.app.state.connectors.table_for(engine.policy, engine.policy_version)


async def _connector_status(
    request: Request, cid: str, policy: Policy, table: RoutingTable, spend: dict[str, float]
) -> ConnectorStatus:
    registry = request.app.state.connectors
    cfg = policy.connectors[cid]
    handle = table.connectors[cid]
    killed = registry.is_killed(cid)
    healthy: bool | None = None
    last_error = registry.last_error(cid)
    if handle.unavailable:
        healthy, last_error = False, last_error or handle.unavailable
    elif not killed and cfg.enabled:
        healthy = await registry.healthy(cid)
    if killed:
        info = registry.kill_info(cid)
        last_error = f"kill switch: {info.reason}" if info else last_error
    return ConnectorStatus(
        id=cid,
        type=cfg.type,
        tier=cfg.tier,
        enabled=cfg.enabled,
        kill_switch=killed,
        healthy=healthy,
        latency_ms_p50=registry.latency_p50(cid),
        last_error=last_error,
        spend_usd_day=round(spend.get(cid, 0.0), 6),
    )


async def _spend_day(request: Request) -> dict[str, float]:
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        return {}
    try:
        return await spend_by_connector(sessions, datetime.now(UTC) - timedelta(days=1))
    except Exception:
        return {}


@router.get("/connectors", response_model=list[ConnectorStatus], tags=["models"], operation_id="listConnectors")
async def connectors(request: Request, p: Viewer) -> list[ConnectorStatus]:
    policy, table = _policy_and_table(request)
    spend = await _spend_day(request)
    return list(
        await asyncio.gather(*(_connector_status(request, cid, policy, table, spend) for cid in policy.connectors))
    )


@router.post(
    "/connectors/{connector_id}/kill-switch",
    response_model=ConnectorStatus,
    tags=["models"],
    operation_id="setKillSwitch",
)
async def kill_switch(request: Request, connector_id: str, body: KillSwitchRequest, p: Admin) -> ConnectorStatus:
    # In-memory, per connector; survives policy reloads. Routes to the degraded local target meanwhile.
    policy, table = _policy_and_table(request)
    if connector_id not in policy.connectors:
        raise HTTPException(404, detail="unknown connector")
    request.app.state.connectors.set_kill_switch(connector_id, body.engaged, body.reason, by=p.username or p.subject)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        await audit.record_event(
            EventType.system_alert,
            severity=Severity.high if body.engaged else Severity.info,
            detail={
                "event": "kill_switch",
                "connector": connector_id,
                "engaged": body.engaged,
                "reason": body.reason,
            },
            principal=p,
        )
    return await _connector_status(request, connector_id, policy, table, await _spend_day(request))


async def _usage_day(request: Request) -> dict[str, dict[str, float]]:
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        return {}
    try:
        return await usage_by_model(sessions, datetime.now(UTC) - timedelta(days=1))
    except Exception:
        return {}


@router.get("/models", response_model=list[ModelInfo], tags=["models"], operation_id="listModelsAdmin")
async def models(request: Request, p: Viewer) -> list[ModelInfo]:
    policy, table = _policy_and_table(request)
    fixed_aliases: dict[str, list[str]] = {}
    for name, alias in policy.aliases.items():
        if alias.strategy == "fixed" and alias.target:
            fixed_aliases.setdefault(alias.target, []).append(name)
    usage = await _usage_day(request)
    out = []
    for m in policy.models:
        cfg = policy.connectors[m.connector]
        handle = table.models[m.id]
        artifact = "n/a" if m.artifact is None else "scanned_ok" if m.artifact.scan_id else "unscanned"
        used = usage.get(m.id, {})
        out.append(
            ModelInfo(
                id=m.id,
                connector=m.connector,
                tier=cfg.tier,
                aliases=[*m.aliases, *fixed_aliases.get(m.id, [])],
                tags=dict(m.tags),
                data_classes=list(m.data_classes),
                pricing=m.pricing.model_dump(exclude_none=True),
                artifact_status=artifact,  # type: ignore[arg-type]
                enabled=m.enabled and cfg.enabled and not request.app.state.connectors.is_killed(m.connector),
                available=handle.unavailable is None and table.connectors[m.connector].unavailable is None,
                role=m.tags.get("role"),
                requests_day=int(used.get("requests", 0)),
                tokens_in_day=int(used.get("tokens_in", 0)),
                tokens_out_day=int(used.get("tokens_out", 0)),
                usd_day=round(used.get("usd", 0.0), 6),
                gpu_seconds_day=round(used.get("gpu_seconds", 0.0), 3),
            )
        )
    return out


# ---------------------------------------------------------------- feed (1D)


@router.get("/feed", response_model=FeedStatus, tags=["feed"], operation_id="getFeedStatus")
async def feed_status(request: Request, p: Viewer) -> FeedStatus:
    # Status of the active signature bundle (version, entries, last sync / error). No docstring on purpose:
    # it would change the generated OpenAPI contract.
    store = getattr(request.app.state, "feed_store", None)
    if store is None:
        not_implemented("feed")
    return store.status()


@router.post("/feed/sync", response_model=FeedStatus, tags=["feed"], operation_id="syncFeed")
async def feed_sync(request: Request, p: Admin) -> FeedStatus:
    # Immediate fetch → verify → swap (demo: add a rule to the feed, sync, next request is blocked).
    sync = getattr(request.app.state, "feed_sync", None)
    if sync is None:
        not_implemented("feed")
    await sync.sync_once()
    return sync.store.status()


def _active_signatures(request: Request) -> list[tuple[CompiledEntry, str]]:
    # The merged active set, as SEC-SIG-01 sees it: bundle entries, plus the policy's offline baseline
    # (`signatures.local_rules`) for ids the feed does not carry. The feed wins on a clash.
    store = getattr(request.app.state, "feed_store", None)
    if store is None:
        not_implemented("feed")
    bundle = store.current()
    out: list[tuple[CompiledEntry, str]] = [(e, "feed") for e in (bundle.entries if bundle else ())]
    engine = request.app.state.engine
    if engine is not None:
        seen = {e.id for e, _ in out}
        local, _errors = compile_entries(engine.policy.signatures.local_rules)
        out.extend((e, "policy") for e in local if e.id not in seen)
    return out


_SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


@router.get(
    "/feed/signatures",
    response_model=list[FeedSignature],
    tags=["feed"],
    operation_id="listFeedSignatures",
    responses=TOTAL_COUNT_RESPONSES,
)
async def feed_signatures(
    request: Request,
    response: Response,
    p: Viewer,
    target: FeedTarget | None = None,
    q: str | None = None,
    limit: int = 500,
) -> list[FeedSignature]:
    # Signatures of the active bundle (+ the policy's offline baseline) with 24 h hit counts from the audit index.
    # Sorted most severe first. (A comment, not a docstring: it would change the generated OpenAPI contract.)
    now = time.time()
    rows = [(e, origin) for e, origin in _active_signatures(request) if q is None or _matches(e, q)]
    sigs = [describe(e, origin=origin, now=now) for e, origin in rows]
    if target is not None:
        sigs = [s for s in sigs if s.target == target]
    sigs.sort(key=lambda s: (-_SEVERITY_ORDER[s.severity], s.id))
    set_total(response, len(sigs))
    sigs = sigs[: max(1, min(limit, 2000))]
    hits = await _hits_24h(request, [s.id for s in sigs])
    return [s.model_copy(update={"hits_24h": hits[s.id][0], "last_hit_at": hits[s.id][1]}) if hits else s for s in sigs]


def _matches(ce: CompiledEntry, q: str) -> bool:
    needle = q.strip().lower()
    e = ce.entry
    return not needle or needle in e.id.lower() or needle in e.description.lower() or needle in e.pattern.lower()


async def _hits_24h(request: Request, ids: list[str]) -> dict:
    sessions = getattr(request.app.state, "db", None)
    if sessions is None or not ids:
        return {}
    try:
        return await rule_hits(sessions, ids, datetime.now(UTC) - timedelta(hours=24))
    except Exception:
        log.exception("could not count signature hits")
        return {}


@router.post(
    "/feed/rules",
    response_model=FeedRuleCreated,
    status_code=201,
    tags=["feed"],
    operation_id="addFeedRule",
    responses={
        409: {"description": "A rule with this id already exists"},
        422: {"description": "The rule is invalid (bad regex, missing field, ...)"},
        502: {"description": "The feed server is unreachable or rejected the request"},
        503: {"description": "Rule editing is not configured"},
    },
)
async def add_feed_rule(request: Request, body: FeedRuleCreate, p: Admin) -> FeedRuleCreated:
    # The feed server stays the source of truth: the rule is published there (new signed bundle), then the gateway
    # syncs it like any other change. (A comment, not a docstring: it would change the generated OpenAPI contract.)
    client: FeedAdminClient | None = getattr(request.app.state, "feed_admin", None)
    sync = getattr(request.app.state, "feed_sync", None)
    store = getattr(request.app.state, "feed_store", None)
    if client is None or sync is None or store is None:
        not_implemented("feed")
    if not client.configured:
        raise HTTPException(503, detail="adding feed rules is not configured (feed URL / ACL_FEED_ADMIN_TOKEN)")
    try:
        entry = build_entry(body)
    except RuleInvalid as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    if any(e.id == entry.id for e, _ in _active_signatures(request)):
        raise HTTPException(409, detail=f"a rule with id {entry.id} already exists")
    try:
        bundle_version = await client.add_entry(entry)
    except FeedAdminError as exc:
        raise HTTPException(exc.status, detail=exc.message) from exc
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        await audit.record_event(
            EventType.feed_update,
            severity=Severity.info,
            detail={  # the pattern itself is not recorded: it may be a literal secret someone wants blocked
                "event": "rule_added",
                "rule_id": entry.id,
                "target": body.target,
                "type": entry.type.value,
                "action": entry.action.value,
                "rule_severity": entry.severity.value,
                "pattern_chars": len(entry.pattern),
                "feed_bundle_version": bundle_version,
                "rule_ids": [entry.id],
            },
            principal=p,
        )
    if body.sync_now:
        await sync.sync_once()
    bundle = store.current()
    synced = bundle is not None and any(e.id == entry.id for e in bundle.entries)
    return FeedRuleCreated(
        rule=describe(compile_entry(entry), origin="feed", hits=(0, None)),
        bundle_version=bundle_version,
        synced=synced,
        feed=store.status(),
    )


# ---------------------------------------------------------------- artifacts (4A)


@router.post("/artifacts/scan", response_model=ArtifactScanResult, tags=["artifacts"], operation_id="scanArtifact")
async def scan_artifact(file: UploadFile, p: Admin) -> ArtifactScanResult:
    not_implemented("artifact scan")


@router.get("/artifacts", response_model=list[ArtifactScanResult], tags=["artifacts"], operation_id="listArtifacts")
async def list_artifacts(p: Viewer) -> list[ArtifactScanResult]:
    not_implemented("artifacts")


# ---------------------------------------------------------------- insights (4B)


@router.get("/insights/clusters", response_model=list[InsightCluster], tags=["insights"], operation_id="listInsights")
async def insights(p: Viewer, group: str | None = None) -> list[InsightCluster]:
    not_implemented("insights")


@router.post(
    "/insights/clusters/{cluster_id}/publish",
    response_model=InsightCluster,
    tags=["insights"],
    operation_id="publishSkill",
)
async def publish(cluster_id: str, body: PublishSkillRequest, p: Admin) -> InsightCluster:
    not_implemented("insights publish")
