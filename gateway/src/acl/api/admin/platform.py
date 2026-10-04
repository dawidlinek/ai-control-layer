"""Admin: approvals (2B), budgets (2D), models/connectors (1A/3B), MCP (2A), feed (1D),
artifacts (4A), insights (4B).

Each section is owned by the phase noted; the route signatures are the contract.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request

from acl.api.deps import ERROR_RESPONSES, Admin, Viewer, not_implemented
from acl.audit.queries import spend_by_connector, usage_by_model
from acl.contracts.admin import (
    ConnectorStatus,
    FeedStatus,
    InsightCluster,
    KillSwitchRequest,
    ModelInfo,
    PublishSkillRequest,
)
from acl.contracts.audit import EventType
from acl.contracts.common import Severity
from acl.policy.models import ModelEntry, Policy
from acl.routing.registry import RoutingTable

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


def _artifact_status(request: Request, m: ModelEntry) -> str:
    """`n/a` without an artifact ref; otherwise from the scan store (4A): scanned_ok | scanned_bad | unscanned."""
    store = getattr(request.app.state, "artifacts", None)
    if m.artifact is None:
        return "n/a"
    return "unscanned" if store is None else store.status(m.artifact)


def _artifact_problem(request: Request, m: ModelEntry) -> str | None:
    store = getattr(request.app.state, "artifacts", None)
    if m.artifact is None:
        return None
    return "artifact is not scanned" if store is None else store.gate_problem(m.artifact)


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
        artifact = _artifact_status(request, m)
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
                available=handle.unavailable is None
                and table.connectors[m.connector].unavailable is None
                and _artifact_problem(request, m) is None,
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
