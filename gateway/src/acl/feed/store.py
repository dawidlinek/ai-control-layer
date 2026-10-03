"""Active signature bundle: compiled entries + version, swapped atomically.

Registered as the `control_deps` service `"signatures"`; the `signatures` control reads `current()` on
every inspection, so a swap takes effect on the very next request (no engine rebuild).
"""

from __future__ import annotations

import enum
import logging
from datetime import UTC, datetime

from acl.contracts.admin import FeedStatus
from acl.contracts.feed import FeedBundle
from acl.feed.compile import CompiledBundle, compile_entries

log = logging.getLogger(__name__)


class InstallOutcome(enum.StrEnum):
    installed = "installed"
    unchanged = "unchanged"  # same version, same content
    not_increasing = "not_increasing"  # lower version than the active bundle
    conflict = "conflict"  # same version, different content


class SignatureStore:
    def __init__(self, source_url: str | None = None) -> None:
        self._bundle: CompiledBundle | None = None
        self._loaded_at: datetime | None = None
        self.source_url = source_url
        self.last_sync_at: datetime | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------ read side

    def current(self) -> CompiledBundle | None:
        return self._bundle

    @property
    def version(self) -> int | None:
        b = self._bundle
        return b.version if b is not None else None

    def status(self) -> FeedStatus:
        b = self._bundle
        return FeedStatus(
            source_url=self.source_url,
            bundle_version=b.version if b else None,
            issued_at=b.issued_at if b else None,
            loaded_at=self._loaded_at,
            entries=len(b.entries) if b else 0,
            verified=b is not None,  # only verified bundles are ever installed
            last_sync_at=self.last_sync_at,
            last_error=self.last_error,
        )

    # ------------------------------------------------------------------ write side

    def record_attempt(self, error: str | None) -> None:
        self.last_sync_at = datetime.now(UTC)
        self.last_error = error

    def install(self, bundle: FeedBundle, digest: str) -> tuple[InstallOutcome, CompiledBundle | None]:
        """Compile and atomically activate a *verified* bundle if its version is greater than the active one."""
        cur = self._bundle
        if cur is not None:
            if bundle.bundle_version < cur.version:
                return InstallOutcome.not_increasing, None
            if bundle.bundle_version == cur.version:
                return (InstallOutcome.unchanged if digest == cur.digest else InstallOutcome.conflict), None
        entries, errors = compile_entries(bundle.entries)
        compiled = CompiledBundle(
            version=bundle.bundle_version,
            entries=entries,
            issued_at=bundle.issued_at,
            errors=errors,
            digest=digest,
        )
        self._bundle = compiled  # single reference assignment: readers see old or new, never a mix
        self._loaded_at = datetime.now(UTC)
        return InstallOutcome.installed, compiled
