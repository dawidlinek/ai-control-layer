"""Persistence and state machine for MCP servers and pinned tool manifests.

Tool status machine (per `(server, upstream tool name)`):

    (first sight, clean)            -> pinned            pinned_hash = current_hash
    (first sight, flagged)          -> quarantined       poisoned description / bad schema pin / hidden chars...
    (first sight, name collision)   -> pending_approval  the later tool is hidden until an admin approves it
    pinned, hash changed            -> quarantined       rug pull: incident + `mcp_drift` event + description diff
    any "not enforcing" outcome     -> drifted           monitor mode: visible and callable, recorded
    quarantined / pending_approval  -> pinned            ONLY by an admin (`approve`): pin := current hash
    pinned / drifted                -> quarantined       admin `quarantine`

Quarantine is sticky: a server that reverts the change does not release the tool (flapping descriptions are a
known evasion); the admin re-approves the current hash.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.controls.mcp.canon import description_diff, normalise_name, schema_changed, tool_hash_of
from acl.controls.mcp.catalog import ToolCatalog
from acl.controls.mcp.pinning import HARD_KINDS
from acl.mcp_proxy.db_models import McpServerRow, McpToolRow

VISIBLE = ("pinned", "drifted")


def unmapped_tool_id(server: str, name: str) -> str:
    return f"{server}:{name}"


@dataclass
class ToolEvent:
    kind: str  # drift | quarantined | collision | pinned | released
    server: str
    name: str
    tool_id: str
    status: str
    reasons: list[str] = field(default_factory=list)
    diff: str | None = None
    old_hash: str | None = None
    new_hash: str | None = None


@dataclass
class ListingOutcome:
    rows: dict[str, McpToolRow]  # name -> row after the update
    events: list[ToolEvent]


def _utc() -> datetime:
    return datetime.now(UTC)


class McpStore:
    def __init__(self, sessions: Callable[[], async_sessionmaker[AsyncSession]]) -> None:
        self._sessions = sessions
        self._locks: dict[str, asyncio.Lock] = {}

    def lock(self, server: str) -> asyncio.Lock:
        return self._locks.setdefault(server, asyncio.Lock())

    # ------------------------------------------------------------------ reads

    async def tools_for(self, server: str) -> dict[str, McpToolRow]:
        async with self._sessions()() as s:
            rows = (await s.execute(select(McpToolRow).where(McpToolRow.server_id == server))).scalars().all()
        return {r.name: r for r in rows}

    async def all_tools(self, server: str | None = None) -> list[McpToolRow]:
        async with self._sessions()() as s:
            stmt = select(McpToolRow).order_by(McpToolRow.server_id, McpToolRow.name)
            if server:
                stmt = stmt.where(McpToolRow.server_id == server)
            return list((await s.execute(stmt)).scalars().all())

    async def get_tool(self, server: str, name: str) -> McpToolRow | None:
        async with self._sessions()() as s:
            return await s.get(McpToolRow, (server, name))

    async def get_by_tool_id(self, tool_id: str) -> McpToolRow | None:
        async with self._sessions()() as s:
            return (await s.execute(select(McpToolRow).where(McpToolRow.tool_id == tool_id))).scalars().first()

    async def other_tool_names(self, server: str) -> dict[str, str]:
        """normalised name -> `server:name` for tools known on OTHER servers (earlier owners of a name)."""
        out: dict[str, str] = {}
        async with self._sessions()() as s:
            rows = (
                await s.execute(
                    select(McpToolRow)
                    .where(McpToolRow.server_id != server, McpToolRow.status.in_(("pinned", "drifted")))
                    .order_by(McpToolRow.first_seen)
                )
            ).scalars()
            for r in rows:
                out.setdefault(normalise_name(r.name), f"{r.server_id}:{r.name}")
        return out

    async def server_rows(self) -> dict[str, McpServerRow]:
        async with self._sessions()() as s:
            return {r.server_id: r for r in (await s.execute(select(McpServerRow))).scalars().all()}

    # ------------------------------------------------------------------ servers

    async def note_server(
        self,
        server: str,
        *,
        transport: str,
        status: str,
        url: str | None = None,
        origin: str | None = None,
        protocol_version: str | None = None,
        capabilities: dict[str, Any] | None = None,
        server_info: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> McpServerRow:
        async with self._sessions()() as s:
            row = await s.get(McpServerRow, server)
            now = _utc()
            if row is None:
                row = McpServerRow(
                    server_id=server,
                    transport=transport,
                    capabilities={},
                    server_info={},
                    status=status,
                    first_seen=now,
                )
                s.add(row)
            row.transport = transport
            row.status = status
            row.last_error = (error or None) and error[:300]  # type: ignore[index]
            if status == "ok":
                row.last_seen = now
                row.bound_url = url or row.bound_url
                row.bound_origin = origin or row.bound_origin
                if protocol_version:
                    row.protocol_version = protocol_version
                if capabilities is not None:
                    row.capabilities = capabilities
                if server_info is not None:
                    row.server_info = server_info
            await s.commit()
            return row

    # ------------------------------------------------------------------ listing / pinning

    async def apply_listing(
        self,
        server: str,
        tools: list[dict[str, Any]],
        flags: dict[str, list[dict[str, str]]],
        *,
        enforce: bool,
        catalog: ToolCatalog,
    ) -> ListingOutcome:
        """Pin / flag every announced tool and return the rows after the update. Caller holds `lock(server)`."""
        events: list[ToolEvent] = []
        out: dict[str, McpToolRow] = {}
        now = _utc()
        async with self._sessions()() as s:
            existing = {
                r.name: r
                for r in (await s.execute(select(McpToolRow).where(McpToolRow.server_id == server))).scalars().all()
            }
            for raw in tools:
                name = raw["name"]
                h = tool_hash_of(raw)
                desc = raw.get("description") if isinstance(raw.get("description"), str) else None
                schema = raw.get("inputSchema") if isinstance(raw.get("inputSchema"), dict) else {}
                entries = flags.get(name, [])
                kinds = {e["kind"] for e in entries}
                row = existing.get(name)
                if row is not None and row.pinned_hash and row.pinned_hash != h and "drift" not in kinds:
                    kinds.add("drift")  # proxy-level pin check even when the control did not flag it
                    entries = [*entries, {"kind": "drift", "detail": "manifest_hash_changed", "rule": "SEC-MCP-01"}]
                reasons = [f"{e['kind']}:{e['detail']}" for e in entries]
                hard = bool(kinds & HARD_KINDS)
                mapped = catalog.resolve(server, name)
                policy_id = mapped[0] if mapped else None
                tool_id = policy_id or unmapped_tool_id(server, name)

                if row is None:
                    row = McpToolRow(
                        server_id=server,
                        name=name,
                        tool_id=tool_id,
                        policy_tool_id=policy_id,
                        status="pinned",
                        current_hash=h,
                        reasons=[],
                        first_seen=now,
                        last_seen=now,
                    )
                    s.add(row)
                    self._set_current(row, h, desc, schema)
                    if not kinds:
                        row.pinned_hash, row.pinned_description, row.pinned_schema = h, desc, schema
                        events.append(ToolEvent("pinned", server, name, tool_id, "pinned", new_hash=h))
                    else:
                        row.status = self._flagged_status(hard, enforce)
                        row.reasons = reasons
                        events.append(
                            ToolEvent(
                                "quarantined" if hard else "collision",
                                server,
                                name,
                                tool_id,
                                row.status,
                                reasons,
                                new_hash=h,
                            )
                        )
                else:
                    row.tool_id, row.policy_tool_id = tool_id, policy_id
                    changed = row.current_hash != h
                    old_status = row.status
                    self._set_current(row, h, desc, schema)
                    row.last_seen = now
                    if row.status == "pinned" and h == row.pinned_hash and not kinds:
                        pass
                    elif row.status == "drifted" and not kinds:
                        # a change that was only recorded (monitor mode) and is clean now: (re)pin the current form
                        row.status, row.reasons, row.description_diff, row.drift_detected_at = "pinned", [], None, None
                        row.pinned_hash, row.pinned_description, row.pinned_schema = h, desc, schema
                        events.append(ToolEvent("released", server, name, tool_id, "pinned", new_hash=h))
                    elif row.status in ("quarantined", "pending_approval"):
                        merged = list(dict.fromkeys([*(row.reasons or []), *reasons]))
                        row.reasons = merged
                        if row.pinned_hash and (changed or not row.description_diff):
                            row.description_diff = self._diff(row, desc, schema)
                    else:  # pinned with a changed hash / new flags, or drifted and still flagged
                        new_status = self._flagged_status(hard or ("drift" in kinds), enforce)
                        if "drift" in kinds and row.pinned_hash:
                            row.drift_detected_at = row.drift_detected_at or now
                            row.description_diff = self._diff(row, desc, schema)
                        row.status = new_status
                        row.reasons = list(dict.fromkeys(reasons))
                        if new_status != old_status or changed:
                            kind = "drift" if "drift" in kinds else ("quarantined" if hard else "collision")
                            events.append(
                                ToolEvent(
                                    kind,
                                    server,
                                    name,
                                    tool_id,
                                    new_status,
                                    row.reasons,
                                    row.description_diff,
                                    old_hash=row.pinned_hash,
                                    new_hash=h,
                                )
                            )
                out[name] = row
            await s.commit()
        return ListingOutcome(out, events)

    @staticmethod
    def _flagged_status(hard: bool, enforce: bool) -> str:
        if not enforce:
            return "drifted"
        return "quarantined" if hard else "pending_approval"

    @staticmethod
    def _set_current(row: McpToolRow, h: str, desc: str | None, schema: dict[str, Any]) -> None:
        row.current_hash, row.current_description, row.current_schema = h, desc, schema

    @staticmethod
    def _diff(row: McpToolRow, desc: str | None, schema: dict[str, Any]) -> str:
        text = description_diff(row.pinned_description, desc)
        if schema_changed(row.pinned_schema, schema):
            text += "\n(inputSchema changed)"
        return text

    # ------------------------------------------------------------------ admin decisions

    async def approve(self, row_key: tuple[str, str], by: str, note: str) -> McpToolRow | None:
        async with self._sessions()() as s:
            row = await s.get(McpToolRow, row_key)
            if row is None:
                return None
            row.status = "pinned"
            row.pinned_hash = row.current_hash
            row.pinned_description = row.current_description
            row.pinned_schema = row.current_schema
            row.description_diff = None
            row.reasons = []
            row.drift_detected_at = None
            row.approved_by, row.approved_at, row.decision_note = by[:255], _utc(), note[:500]
            await s.commit()
            return row

    async def quarantine(self, row_key: tuple[str, str], by: str, note: str) -> McpToolRow | None:
        async with self._sessions()() as s:
            row = await s.get(McpToolRow, row_key)
            if row is None:
                return None
            row.status = "quarantined"
            row.reasons = list(dict.fromkeys([*(row.reasons or []), "manual:quarantined_by_admin"]))
            row.approved_by, row.approved_at, row.decision_note = by[:255], _utc(), note[:500]
            await s.commit()
            return row
