"""Feed polling: fetch → verify → compile → swap; failures keep the last good bundle (concept §9.2).

`sync_once()` is what the poll loop and `POST /admin/v1/feed/sync` call. Verification failures emit a
`feed_verify_failed` audit event (throttled: one per distinct failure), successful swaps a `feed_update`.
Network errors only update the status (`last_error`), they are not verification failures.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from acl.audit.sink import AuditSink
from acl.contracts.audit import EventType
from acl.contracts.canonical import bundle_digest
from acl.contracts.common import Severity
from acl.feed.store import InstallOutcome, SignatureStore
from acl.feed.verify import FeedVerifyError, verify_bundle

log = logging.getLogger(__name__)

MAX_BUNDLE_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class FeedConfig:
    url: str
    poll_s: float = 30.0
    verify: str = "sha256"
    public_key: str | None = None


@dataclass(frozen=True)
class SyncResult:
    outcome: str  # updated | unchanged | rejected | error | unconfigured
    version: int | None = None
    code: str | None = None


class FeedSync:
    def __init__(
        self,
        store: SignatureStore,
        config: Callable[[], FeedConfig | None],
        audit: Callable[[], AuditSink | None] = lambda: None,
        *,
        timeout_s: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.store = store
        self._config = config
        self._audit = audit
        self._timeout_s = timeout_s
        self._transport = transport
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._last_failure: tuple[str, str] | None = None

    # ------------------------------------------------------------------ one sync

    async def sync_once(self) -> SyncResult:
        async with self._lock:
            return await self._sync()

    async def _sync(self) -> SyncResult:
        cfg = self._config()
        if cfg is None:
            self.store.record_attempt("no feed configured")
            return SyncResult("unconfigured", self.store.version, "unconfigured")
        self.store.source_url = cfg.url
        try:
            raw = await self._fetch(cfg.url)
        except (httpx.HTTPError, ValueError) as exc:
            self.store.record_attempt(f"fetch failed: {type(exc).__name__}")
            log.warning("feed fetch failed (%s)", type(exc).__name__)
            return SyncResult("error", self.store.version, "fetch_failed")

        digest = bundle_digest(raw) if isinstance(raw, dict) else ""
        try:
            if not isinstance(raw, dict):
                raise FeedVerifyError("schema", "bundle is not a JSON object")
            bundle = verify_bundle(raw, mode=cfg.verify, public_key=cfg.public_key)
        except FeedVerifyError as exc:
            return await self._reject(exc.code, digest, raw)

        outcome, compiled = self.store.install(bundle, digest)
        if outcome == InstallOutcome.unchanged:
            self.store.record_attempt(None)
            self._last_failure = None
            return SyncResult("unchanged", self.store.version)
        if outcome in (InstallOutcome.not_increasing, InstallOutcome.conflict):
            code = "version_not_increasing" if outcome == InstallOutcome.not_increasing else "version_conflict"
            return await self._reject(code, digest, raw)

        assert compiled is not None
        self._last_failure = None
        self.store.record_attempt(f"{len(compiled.errors)} signature(s) failed to compile" if compiled.errors else None)
        await self._emit(
            EventType.feed_update,
            Severity.info,
            {"bundle_version": compiled.version, "entries": len(compiled.entries), "skipped": len(compiled.errors)},
        )
        log.info("signature bundle v%s active (%d entries)", compiled.version, len(compiled.entries))
        return SyncResult("updated", compiled.version)

    async def _reject(self, code: str, digest: str, raw: Any) -> SyncResult:
        version = raw.get("bundle_version") if isinstance(raw, dict) else None
        self.store.record_attempt(f"bundle rejected: {code}")
        key = (code, digest)
        if key != self._last_failure:  # do not repeat the same alert every poll
            self._last_failure = key
            await self._emit(
                EventType.feed_verify_failed,
                Severity.high,
                {
                    "code": code,
                    "offered_version": version if isinstance(version, int) else None,
                    "active_version": self.store.version,
                    "source": self.store.source_url,
                },
            )
        log.warning("signature bundle rejected (%s); keeping version %s", code, self.store.version)
        return SyncResult("rejected", self.store.version, code)

    async def _fetch(self, url: str) -> Any:
        # TLS settings (certifi bundle, ~100 ms to load) only matter for https feeds
        async with httpx.AsyncClient(
            timeout=self._timeout_s,
            follow_redirects=False,
            transport=self._transport,
            verify=url.lower().startswith("https://"),
        ) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            if len(resp.content) > MAX_BUNDLE_BYTES:
                raise ValueError("bundle too large")
            return resp.json()

    async def _emit(self, event: EventType, severity: Severity, detail: dict[str, Any]) -> None:
        sink = self._audit()
        if sink is None:
            return
        try:
            await sink.record_event(event, severity=severity, detail=detail)
        except Exception:  # auditing must never block a swap or crash the poller
            log.exception("could not record %s", event.value)

    # ------------------------------------------------------------------ poll loop

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="feed-sync")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _run(self) -> None:
        while True:
            try:
                await self.sync_once()
            except Exception:  # keep polling whatever happens
                log.exception("feed sync crashed")
            cfg = self._config()
            await asyncio.sleep(cfg.poll_s if cfg else 30.0)
