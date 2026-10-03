"""Policy sources (concept §11 scalability note).

The service reads policy through `PolicySource`; `FileSource` (a directory of YAML files) is the hackathon
implementation. A GitOps source (read from a checked-out repo, write = open a pull request) or a DB-backed
source can implement the same protocol without touching the engine, compiler, writer or API.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from acl.contracts.admin import PolicyError, PolicyFileInfo
from acl.policy.loader import FILE_NAME_RE, PolicyLoadError, content_hash

log = logging.getLogger(__name__)

_TMP_PREFIX = ".acl-tmp-"


def valid_file_name(name: str) -> bool:
    return bool(FILE_NAME_RE.fullmatch(name))


@dataclass(frozen=True)
class SourceFile:
    name: str
    content: str  # LF-normalised, BOM stripped
    modified_at: datetime

    @property
    def version(self) -> str:
        return content_hash(self.content)

    @property
    def size(self) -> int:
        return len(self.content.encode("utf-8"))

    def info(self) -> PolicyFileInfo:
        return PolicyFileInfo(name=self.name, version=self.version, size=self.size, modified_at=self.modified_at)


@runtime_checkable
class PolicySource(Protocol):
    """Where policy files live. Read/write are synchronous (small local files); `watch` is async."""

    writable: bool

    def read_files(self) -> dict[str, SourceFile]:
        """All policy files by name. Raises `PolicyLoadError` for unreadable files."""
        ...

    def write_file(self, name: str, content: str) -> None:
        """Atomically replace (or create) one file."""
        ...

    def delete_file(self, name: str) -> None: ...

    def watch(self, stop: asyncio.Event) -> AsyncIterator[None]:
        """Yield (once per debounced burst of changes) until `stop` is set."""
        ...


def normalise_text(raw: bytes) -> str:
    """UTF-8 (BOM tolerated), CRLF/CR -> LF so the content hash does not depend on the editor's line endings."""
    text = raw.decode("utf-8-sig")
    return text.replace("\r\n", "\n").replace("\r", "\n")


class FileSource:
    """A directory of `*.yaml` files. Names must match `^[a-z0-9_-]+\\.yaml$`; anything else is ignored."""

    writable = True

    def __init__(
        self,
        directory: Path,
        *,
        force_polling: bool = False,
        poll_delay_ms: int = 300,
        debounce_ms: int = 200,
        step_ms: int = 50,
        rescan_interval_s: float = 5.0,
    ) -> None:
        self.directory = Path(directory)
        self.force_polling = force_polling
        self.poll_delay_ms = poll_delay_ms
        self.debounce_ms = debounce_ms
        self.step_ms = step_ms
        self.rescan_interval_s = rescan_interval_s
        self._warned: set[str] = set()

    # ------------------------------------------------------------ read

    def read_files(self) -> dict[str, SourceFile]:
        files: dict[str, SourceFile] = {}
        errors: list[PolicyError] = []
        try:
            entries = sorted(self.directory.glob("*.yaml"))
        except OSError as exc:
            raise PolicyLoadError(
                [PolicyError(message=f"cannot read policy directory: {exc.strerror or exc}")]
            ) from exc
        for path in entries:
            if not valid_file_name(path.name):
                if path.name not in self._warned:
                    self._warned.add(path.name)
                    log.warning("ignoring policy file %r: name must match %s", path.name, FILE_NAME_RE.pattern)
                continue
            try:
                stat = path.stat()
                text = normalise_text(path.read_bytes())
            except UnicodeDecodeError:
                errors.append(PolicyError(file=path.name, message="file is not valid UTF-8"))
                continue
            except OSError as exc:
                errors.append(PolicyError(file=path.name, message=f"cannot read file: {exc.strerror or exc}"))
                continue
            files[path.name] = SourceFile(path.name, text, datetime.fromtimestamp(stat.st_mtime, UTC))
        if errors:
            raise PolicyLoadError(errors)
        return files

    # ------------------------------------------------------------ write

    def _path(self, name: str) -> Path:
        if not valid_file_name(name):
            raise ValueError("invalid policy file name")
        path = (self.directory / name).resolve()
        if path.parent != self.directory.resolve():  # symlink / traversal guard
            raise ValueError("invalid policy file name")
        return path

    def write_file(self, name: str, content: str) -> None:
        """temp file in the same directory + fsync + `os.replace`; LF line endings."""
        path = self._path(name)
        tmp = path.with_name(f"{_TMP_PREFIX}{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            self._replace(tmp, path)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()

    @staticmethod
    def _replace(tmp: Path, dest: Path) -> None:
        for attempt in range(6):  # Windows: the target may be briefly open in another process (AV, editor)
            try:
                os.replace(tmp, dest)
                return
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def delete_file(self, name: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            self._path(name).unlink()

    # ------------------------------------------------------------ watch

    def _watch_filter(self) -> Callable[[object, str], bool]:
        def accept(_change: object, path: str) -> bool:
            return valid_file_name(Path(path).name)

        return accept

    async def watch(self, stop: asyncio.Event) -> AsyncIterator[None]:  # type: ignore[override]
        """Yield after each debounced burst of changes to policy files (and on the periodic safety rescan)."""
        from watchfiles import awatch

        queue: asyncio.Queue[None] = asyncio.Queue()

        async def pump() -> None:
            while not stop.is_set():
                try:
                    async for _changes in awatch(
                        self.directory,
                        debounce=self.debounce_ms,
                        step=self.step_ms,
                        watch_filter=self._watch_filter(),
                        stop_event=stop,
                        force_polling=self.force_polling,
                        poll_delay_ms=self.poll_delay_ms,
                        rust_timeout=500,
                        yield_on_timeout=False,
                    ):
                        queue.put_nowait(None)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("policy watcher failed; restarting in 1 s")
                    await asyncio.sleep(1.0)

        task = asyncio.create_task(pump(), name="policy-watch-pump")
        try:
            # Edits made between the caller's initial read and the OS watcher being armed would be missed:
            # look once more shortly after arming (a poller needs a full poll cycle to take its first snapshot).
            await asyncio.sleep(0.25 + (self.poll_delay_ms / 1000 if self.force_polling else 0))
            if not stop.is_set():
                yield None
            while not stop.is_set():
                try:
                    timeout = self.rescan_interval_s if self.rescan_interval_s > 0 else None
                    await asyncio.wait_for(queue.get(), timeout=timeout)
                except TimeoutError:
                    pass  # periodic rescan
                if stop.is_set():
                    break
                while not queue.empty():  # coalesce
                    queue.get_nowait()
                yield None
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
