"""Version snapshots: every distinct successfully loaded policy version, with author, source and diff."""

from __future__ import annotations

import difflib
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.contracts.admin import PolicyVersion, PolicyVersionDetail
from acl.policy.db_models import PolicyVersionRow


def diff_files(old: dict[str, str] | None, new: dict[str, str]) -> tuple[str, list[str]]:
    """Unified diff of every changed file (`a/<name>` -> `b/<name>`) and the names that changed.

    `old=None` (first snapshot): no diff, every file counts as changed."""
    if old is None:
        return "", sorted(new)
    chunks: list[str] = []
    changed: list[str] = []
    for name in sorted(set(old) | set(new)):
        before, after = old.get(name), new.get(name)
        if before == after:
            continue
        changed.append(name)
        chunks.extend(
            difflib.unified_diff(
                (before or "").splitlines(keepends=True),
                (after or "").splitlines(keepends=True),
                fromfile=f"a/{name}" if before is not None else "/dev/null",
                tofile=f"b/{name}" if after is not None else "/dev/null",
            )
        )
        if chunks and not chunks[-1].endswith("\n"):
            chunks[-1] += "\n\\ No newline at end of file\n"
    return "".join(chunks), changed


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)  # SQLite drops tzinfo


def _summary(row: PolicyVersionRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "version": row.version,
        "created_at": _aware(row.created_at),
        "author": row.author,
        "source": row.source,
        "message": row.message or "",
        "reason": row.reason,
        "files_changed": list(row.files_changed or []),
    }


class VersionStore:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sm = sessionmaker

    async def latest(self) -> PolicyVersionRow | None:
        async with self._sm() as session:
            return (
                await session.execute(select(PolicyVersionRow).order_by(PolicyVersionRow.id.desc()).limit(1))
            ).scalar()

    async def add(
        self,
        *,
        version: str,
        source: str,
        author: str | None,
        message: str,
        files: dict[str, str],
        reason: str | None = None,
        previous_files: dict[str, str] | None,
    ) -> PolicyVersionRow:
        diff, changed = diff_files(previous_files, files)
        row = PolicyVersionRow(
            version=version,
            created_at=datetime.now(UTC),
            author=author,
            source=source,
            message=message,
            reason=reason,
            files_changed=changed,
            files=dict(files),
            diff=diff,
        )
        async with self._sm() as session:
            session.add(row)
            await session.commit()
        return row

    async def list(self, limit: int = 50) -> list[PolicyVersion]:
        async with self._sm() as session:
            rows = (
                (await session.execute(select(PolicyVersionRow).order_by(PolicyVersionRow.id.desc()).limit(limit)))
                .scalars()
                .all()
            )
        return [PolicyVersion(**_summary(r)) for r in rows]

    async def get_row(self, version_id: int) -> PolicyVersionRow | None:
        async with self._sm() as session:
            return cast("PolicyVersionRow | None", await session.get(PolicyVersionRow, version_id))

    async def get(self, version_id: int) -> PolicyVersionDetail | None:
        row = await self.get_row(version_id)
        if row is None:
            return None
        return PolicyVersionDetail(**_summary(row), diff=row.diff or "", files=dict(row.files or {}))
