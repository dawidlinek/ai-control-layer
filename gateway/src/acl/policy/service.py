"""PolicyService: load -> compile -> atomic swap, last-good fallback, versions, events (concept §11.1).

Lifecycle (`acl.policy.wiring`): `start()` loads the policy directory and sets `app.state.engine`; a watcher
reloads on change. A reload never half-applies: the candidate is parsed, validated, its controls checked and
the Engine built *before* `app.state.engine` is reassigned (one attribute assignment = the atomic swap).
Requests already running keep the Engine instance they started with; the old instance is closed after a
grace period. On any failure the last good engine stays in force and the errors are kept in
`status().last_error` and emitted as `policy_reload_failed`.

All mutations (reloads and panel writes) are serialised by `self.lock`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from acl.contracts.admin import (
    DryRunRequest,
    DryRunResponse,
    PolicyError,
    PolicyFileContent,
    PolicyFileInfo,
    PolicyStatus,
    PolicyVersion,
    PolicyVersionDetail,
    ValidateResponse,
)
from acl.contracts.audit import EventType
from acl.contracts.common import Severity
from acl.contracts.inspection import Principal
from acl.controls.base import ControlRegistry, registry
from acl.engine.engine import Engine
from acl.policy.compiler import Compiled, compile_texts
from acl.policy.config import PolicyOptions
from acl.policy.errors import FileNotFound, InvalidFileName, LockedControl, Unavailable, ValidationFailed
from acl.policy.loader import LoadedPolicy, PolicyLoadError, compute_version
from acl.policy.locks import LockViolation, locked_violations
from acl.policy.source import PolicySource, SourceFile, normalise_text, valid_file_name
from acl.policy.versions import VersionStore

log = logging.getLogger(__name__)

Source = Literal["file", "panel", "rollback", "startup"]
MARK_TTL_S = 30.0


@dataclass(frozen=True)
class Attribution:
    """Who/why for the next reload that produces a given version (set by the writer before it touches disk)."""

    source: Source
    author: str | None
    message: str
    principal: Principal | None = None


def author_of(principal: Principal | None) -> str | None:
    return (principal.username or principal.subject) if principal is not None else None


class PolicyService:
    def __init__(
        self,
        app: Any,
        source: PolicySource,
        options: PolicyOptions | None = None,
        control_registry: ControlRegistry = registry,
    ) -> None:
        self.app = app
        self.source = source
        self.options = options or PolicyOptions()
        self.registry = control_registry
        self.lock = asyncio.Lock()
        self.versions: VersionStore | None = None

        self._loaded: LoadedPolicy | None = None
        self._texts: dict[str, str] = {}
        self._loaded_at = datetime.now(UTC)
        self._source: Source = "startup"
        self._last_error: list[PolicyError] = []
        self._last_failure_key: str | None = None
        self._marks: dict[str, tuple[Attribution, float]] = {}
        self._stop = asyncio.Event()
        self._watch_task: asyncio.Task[None] | None = None
        self._retiring: dict[asyncio.Task[None], Engine] = {}

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self._stop = asyncio.Event()
        sessionmaker = getattr(self.app.state, "db", None)
        self.versions = VersionStore(sessionmaker) if sessionmaker is not None else None
        async with self.lock:
            await self.reload_locked("startup")
        if self.options.watch:
            self._watch_task = asyncio.create_task(self._watch_loop(), name="policy-watcher")

    async def stop(self) -> None:
        self._stop.set()
        if self._watch_task is not None:
            self._watch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._watch_task
            self._watch_task = None
        for task, engine in list(self._retiring.items()):
            task.cancel()
            await self._close(engine)
        self._retiring.clear()

    async def _watch_loop(self) -> None:
        async for _ in self.source.watch(self._stop):
            try:
                await self.reload()
            except Exception:  # the watcher must never die
                log.exception("policy reload crashed")

    # ------------------------------------------------------------ read side

    @property
    def loaded(self) -> LoadedPolicy | None:
        return self._loaded

    def _engine_factory(self) -> Any:
        return self.app.state.build_engine

    def current_files(self) -> dict[str, SourceFile]:
        try:
            return self.source.read_files()
        except PolicyLoadError as exc:
            raise ValidationFailed(exc.errors) from exc

    def list_files(self) -> list[PolicyFileInfo]:
        return [f.info() for f in self.current_files().values()]

    def get_file(self, name: str) -> PolicyFileContent:
        if not valid_file_name(name):
            raise FileNotFound("policy file")
        f = self.current_files().get(name)
        if f is None:
            raise FileNotFound("policy file")
        return PolicyFileContent(**f.info().model_dump(), content=f.content)

    async def status(self) -> PolicyStatus:
        try:
            files = self.list_files()
        except ValidationFailed:
            files = []
        loaded = self._loaded
        return PolicyStatus(
            version=loaded.version if loaded else "",
            loaded_at=self._loaded_at,
            source=self._source,
            files=files,
            last_error=list(self._last_error),
            locked_controls=sorted(loaded.policy.locked_control_ids()) if loaded else [],
        )

    async def list_versions(self, limit: int = 50) -> list[PolicyVersion]:
        return await self._store().list(max(1, min(limit, 500)))

    async def get_version(self, version_id: int) -> PolicyVersionDetail:
        detail = await self._store().get(version_id)
        if detail is None:
            raise FileNotFound("policy version")
        return detail

    def _store(self) -> VersionStore:
        if self.versions is None:
            raise Unavailable("version history is unavailable (no database)")
        return self.versions

    # ------------------------------------------------------------ candidates

    def _compile(self, texts: dict[str, str]) -> Compiled:
        return compile_texts(texts, self._engine_factory(), self.registry)

    def candidate_texts(self, overlay: dict[str, str]) -> dict[str, str]:
        """Current files (disk; the loaded set if the disk cannot be read) overlaid with `overlay`."""
        for name in overlay:
            if not valid_file_name(name):
                raise InvalidFileName(name)
        try:
            base = {n: f.content for n, f in self.source.read_files().items()}
        except PolicyLoadError:
            base = dict(self._texts)
        return {**base, **{n: normalise_text(c.encode("utf-8")) for n, c in overlay.items()}}

    async def compile_candidate(self, texts: dict[str, str], *, check_locks: bool = True) -> Compiled:
        """Compile (validate + build engine); raises ValidationFailed / LockedControl. Caller owns the engine."""
        try:
            compiled = self._compile(texts)
        except PolicyLoadError as exc:
            raise ValidationFailed(exc.errors) from exc
        if check_locks and self._loaded is not None:
            violations = locked_violations(self._loaded.policy, compiled.policy)
            if violations:
                await compiled.discard()
                raise LockedControl(violations)
        return compiled

    async def validate(self, files: dict[str, str]) -> ValidateResponse:
        try:
            texts = self.candidate_texts(files)
        except InvalidFileName as exc:
            return ValidateResponse(valid=False, errors=[PolicyError(file=exc.name, message=exc.message)])
        try:
            compiled = await self.compile_candidate(texts)
        except ValidationFailed as exc:
            return ValidateResponse(valid=False, errors=exc.errors)
        except LockedControl as exc:
            return ValidateResponse(valid=False, errors=_lock_errors(exc.violations))
        await compiled.discard()
        return ValidateResponse(valid=True, candidate_version=compiled.version)

    async def dry_run(self, req: DryRunRequest) -> DryRunResponse:
        from acl.policy.dryrun import run_dry_run

        return await run_dry_run(self, req)

    # ------------------------------------------------------------ reload

    async def reload(self) -> bool:
        """Re-read the source and swap if the content changed (watcher / safety rescan). True if swapped."""
        async with self.lock:
            return await self.reload_locked("file")

    def expect(self, version: str, attribution: Attribution) -> None:
        """Called by the writer before it writes files: the reload that yields `version` is attributed to it."""
        now = time.monotonic()
        self._marks = {v: m for v, m in self._marks.items() if m[1] > now}
        self._marks[version] = (attribution, now + MARK_TTL_S)

    async def reload_locked(self, source: Source, *, retry: bool = True) -> bool:
        try:
            files = self.source.read_files()
            if not files:
                raise PolicyLoadError([PolicyError(message="no policy files found")])
            texts = {n: f.content for n, f in files.items()}
            version = compute_version(texts)
            if self._loaded is not None and self._loaded.version == version:
                self.clear_error()  # disk equals what is in force (e.g. a broken edit was reverted)
                return False
            attribution = self._marks.pop(version, (None, 0.0))[0] or Attribution(source, None, "")
            compiled = self._compile(texts)
        except PolicyLoadError as exc:
            if source == "file" and retry and self.options.settle_ms > 0:
                await asyncio.sleep(self.options.settle_ms / 1000)  # editor may still be mid-save: look once more
                return await self.reload_locked(source, retry=False)
            await self._record_failure(exc.errors, source)
            return False
        await self.swap(compiled, texts, attribution)
        return True

    # ------------------------------------------------------------ swap

    async def swap(self, compiled: Compiled, texts: dict[str, str], attribution: Attribution) -> None:
        """Atomic swap + snapshot + `policy_change` event. Caller holds the lock."""
        previous = self._loaded
        previous_texts = self._texts
        old_engine: Engine | None = getattr(self.app.state, "engine", None)

        self.app.state.engine = compiled.engine  # <- the atomic swap
        self._loaded, self._texts = compiled.loaded, dict(texts)
        self._loaded_at = datetime.now(UTC)
        self._source = attribution.source
        self.clear_error()
        if old_engine is not None and old_engine is not compiled.engine:
            self._retire(old_engine)

        violations = locked_violations(previous.policy, compiled.policy) if previous else []
        version_id = await self._snapshot(compiled.version, texts, attribution)
        changed = sorted(n for n in set(previous_texts) | set(texts) if previous_texts.get(n) != texts.get(n))
        detail: dict[str, Any] = {
            "version": compiled.version,
            "previous_version": previous.version if previous else None,
            "source": attribution.source,
            "author": attribution.author,
            "message": attribution.message,
            "files_changed": changed if previous else sorted(texts),
            "version_id": version_id,
            "locked_control_modified": [v.as_dict() for v in violations],
        }
        log.info(
            "policy %s active (source=%s, files=%s)", compiled.version, attribution.source, detail["files_changed"]
        )
        await self._emit(
            EventType.policy_change,
            Severity.high if violations else Severity.info,
            detail,
            attribution.principal,
        )

    async def _snapshot(self, version: str, texts: dict[str, str], attribution: Attribution) -> int | None:
        if self.versions is None:
            return None
        try:
            latest = await asyncio.wait_for(self.versions.latest(), self.options.snapshot_timeout_s)
            if latest is not None and latest.version == version:
                return latest.id
            row = await asyncio.wait_for(
                self.versions.add(
                    version=version,
                    source=attribution.source,
                    author=attribution.author,
                    message=attribution.message,
                    files=texts,
                    previous_files=dict(latest.files) if latest is not None else None,
                ),
                self.options.snapshot_timeout_s,
            )
            return row.id
        except Exception:
            log.exception("could not snapshot policy version %s", version)
            return None

    # ------------------------------------------------------------ failures & events

    def clear_error(self) -> None:
        self._last_error = []
        self._last_failure_key = None

    async def _record_failure(self, errors: list[PolicyError], source: Source) -> None:
        self._last_error = errors
        key = "|".join(f"{e.file}:{e.line}:{e.path}:{e.message}" for e in errors)
        log.error(
            "policy reload failed (%d errors); keeping %s",
            len(errors),
            self._loaded.version if self._loaded else "nothing",
        )
        if key == self._last_failure_key:
            return  # same broken content seen again (e.g. several watcher events): alert once
        self._last_failure_key = key
        detail = {
            "source": source,
            "kept_version": self._loaded.version if self._loaded else None,
            "errors": [e.model_dump(mode="json", exclude_none=True) for e in errors],
        }
        await self._emit(EventType.policy_reload_failed, Severity.high, detail, None)

    async def _emit(self, event_type: EventType, severity: Severity, detail: dict[str, Any], principal: Any) -> None:
        audit = getattr(self.app.state, "audit", None)
        if audit is None:
            log.info("audit sink not available; %s not recorded", event_type.value)
            return
        try:
            await audit.record_event(event_type, severity=severity, detail=detail, principal=principal)
        except Exception:
            log.exception("could not record %s", event_type.value)

    # ------------------------------------------------------------ engine retirement

    def _retire(self, engine: Engine) -> None:
        async def later() -> None:
            try:
                await asyncio.sleep(self.options.retire_grace_s)
                await self._close(engine)
            finally:
                self._retiring.pop(task, None)

        task = asyncio.create_task(later(), name="policy-retire-engine")
        self._retiring[task] = engine

    @staticmethod
    async def _close(engine: Engine) -> None:
        try:
            await engine.aclose()
        except Exception:
            log.exception("closing retired engine failed")


def _lock_errors(violations: list[LockViolation]) -> list[PolicyError]:
    return [
        PolicyError(
            path=f"controls.{v.control_id}",
            message=f"locked control {v.control_id} cannot be changed from the panel ({', '.join(v.changes)})",
        )
        for v in violations
    ]


__all__ = ["Attribution", "PolicyService", "author_of"]
