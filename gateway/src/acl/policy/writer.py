"""The single policy writer (concept §11.1).

Everything that changes policy files through the gateway (panel PUT, `patch_file`, rollback) goes through
`PolicyWriter`: optimistic locking on the file's content hash -> validate the *whole candidate set*
(syntax, schema, cross-references, control types and params, engine build) -> org-lock check -> atomic file
replace (temp file + `os.replace`, LF line endings) -> swap + snapshot + event, all under the service lock so
the watcher never observes a half-written set.

Hand-written comments survive because (a) `PUT` stores the submitted text verbatim and (b) `patch_file`
edits through ruamel.yaml round-trip (see `yamledit`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from acl.contracts.admin import PolicyError, PolicyStatus
from acl.contracts.inspection import Principal
from acl.policy.errors import (
    FileNotFound,
    InvalidFileName,
    PolicyServiceError,
    StaleVersion,
    ValidationFailed,
)
from acl.policy.loader import PolicyLoadError, compute_version
from acl.policy.service import Attribution, PolicyService, Source, author_of
from acl.policy.source import normalise_text, valid_file_name
from acl.policy.yamledit import PatchError, PathOp, patch_text

log = logging.getLogger(__name__)

MAX_FILE_CHARS = 1_000_000
NEW_FILE = "new"
"""`base_version` for creating a file that does not exist yet."""


class WriteFailed(PolicyServiceError):
    status_code = 500
    code = "write_failed"


class PolicyWriter:
    def __init__(self, service: PolicyService) -> None:
        self.service = service

    # ------------------------------------------------------------ public

    async def write_file(
        self, name: str, content: str, base_version: str, principal: Principal | None, message: str = ""
    ) -> PolicyStatus:
        """Replace one file with `content` (verbatim apart from LF normalisation)."""
        self._check_name(name)
        if len(content) > MAX_FILE_CHARS:
            raise ValidationFailed([PolicyError(file=name, message=f"file is larger than {MAX_FILE_CHARS} characters")])
        async with self.service.lock:
            disk = self.service.current_files()
            self._check_base(name, disk, base_version)
            candidate = {n: f.content for n, f in disk.items()}
            candidate[name] = normalise_text(content.encode("utf-8"))
            await self._commit(candidate, (), "panel", principal, message)
        return await self.service.status()

    async def patch_file(
        self,
        name: str,
        ops: Sequence[PathOp],
        principal: Principal | None,
        base_version: str | None = None,
        message: str = "",
    ) -> PolicyStatus:
        """Structured edit (set/delete at a YAML path) applied with round-trip preservation of comments/layout.

        `base_version=None` skips the optimistic-lock check (the patch is applied to whatever is on disk)."""
        self._check_name(name)
        async with self.service.lock:
            disk = self.service.current_files()
            if name not in disk:
                raise FileNotFound("policy file")
            if base_version is not None:
                self._check_base(name, disk, base_version)
            try:
                patched = patch_text(disk[name].content, ops)
            except PatchError as exc:
                raise ValidationFailed([PolicyError(file=name, message=f"cannot apply edit: {exc}")]) from exc
            candidate = {n: f.content for n, f in disk.items()}
            candidate[name] = patched
            await self._commit(candidate, (), "panel", principal, message)
        return await self.service.status()

    async def patch_files(
        self,
        edits: Mapping[str, Sequence[PathOp]],
        principal: Principal | None,
        base_version: str | None = None,
        message: str = "",
    ) -> PolicyStatus:
        """Atomic multi-file structured edit: every file is patched (comments preserved), the whole candidate set
        is validated and committed as ONE new policy version, or nothing changes.

        `base_version` is the POLICY version (`PolicyStatus.version`), not a file hash; a mismatch raises
        `StaleVersion`. `None` skips the check."""
        for name in edits:
            self._check_name(name)
        async with self.service.lock:
            self.check_policy_version(base_version)
            disk = self.service.current_files()
            candidate = {n: f.content for n, f in disk.items()}
            candidate.update(self._patched(disk, edits))
            await self._commit(candidate, (), "panel", principal, message)
        return await self.service.status()

    def preview_patch(self, edits: Mapping[str, Sequence[PathOp]]) -> dict[str, str]:
        """Read-only: the texts of the files `edits` would change (patched from what is on disk). No write, no swap."""
        for name in edits:
            self._check_name(name)
        return self._patched(self.service.current_files(), edits)

    def check_policy_version(self, base_version: str | None) -> None:
        """`StaleVersion` unless `base_version` is the version in force (`None` = no check)."""
        if base_version is None:
            return
        loaded = self.service.loaded
        current = loaded.version if loaded is not None else ""
        if base_version != current:
            raise StaleVersion("policy", current)

    async def rollback(self, version_id: int, principal: Principal | None, message: str = "") -> PolicyStatus:
        """Restore the files of a stored version (files that were part of the running set but are not in the
        target are removed; unrelated files on disk are left alone)."""
        store = self.service.versions
        if store is None:
            raise FileNotFound("policy version")
        row = await store.get_row(version_id)
        if row is None:
            raise FileNotFound("policy version")
        target = {n: str(c) for n, c in (row.files or {}).items()}
        async with self.service.lock:
            disk = self.service.current_files()
            running = set(self.service._texts)
            candidate = {n: f.content for n, f in disk.items() if n in target or n not in running}
            candidate.update(target)
            deletions = tuple(sorted(n for n in running if n not in target and n in disk))
            note = f"rollback to version #{version_id} ({row.version})"
            await self._commit(candidate, deletions, "rollback", principal, f"{note}: {message}" if message else note)
        return await self.service.status()

    # ------------------------------------------------------------ internals

    @staticmethod
    def _patched(disk: dict, edits: Mapping[str, Sequence[PathOp]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, ops in edits.items():
            if name not in disk:
                raise FileNotFound("policy file")
            try:
                out[name] = patch_text(disk[name].content, ops)
            except PatchError as exc:
                raise ValidationFailed([PolicyError(file=name, message=f"cannot apply edit: {exc}")]) from exc
        return out

    @staticmethod
    def _check_name(name: str) -> None:
        if not valid_file_name(name):
            raise InvalidFileName(name)

    @staticmethod
    def _check_base(name: str, disk: dict, base_version: str) -> None:
        existing = disk.get(name)
        if existing is None:
            if base_version != NEW_FILE:
                raise FileNotFound("policy file")
        elif base_version != existing.version:
            raise StaleVersion(name, existing.version)

    async def _commit(
        self,
        candidate: dict[str, str],
        deletions: Sequence[str],
        source: Source,
        principal: Principal | None,
        message: str,
    ) -> None:
        svc = self.service
        attribution = Attribution(source, author_of(principal), message, principal)
        compiled = await svc.compile_candidate({n: t for n, t in candidate.items() if n not in deletions})
        disk = svc.current_files()
        svc.expect(compiled.version, attribution)
        try:
            for name, text in candidate.items():
                if name in deletions:
                    continue
                if name not in disk or disk[name].content != text:
                    svc.source.write_file(name, text)
            for name in deletions:
                svc.source.delete_file(name)
            files = svc.source.read_files()
        except (OSError, PolicyLoadError) as exc:
            await compiled.discard()
            log.exception("policy write failed")
            raise WriteFailed("could not write policy files") from exc
        texts = {n: f.content for n, f in files.items()}
        if svc.loaded is not None and compiled.version == svc.loaded.version:
            await compiled.discard()  # nothing changes in force (identical content, or a repair of a broken disk)
            svc.clear_error()
            return
        if compute_version(texts) != compiled.version:
            # Someone edited the directory while we wrote: do not swap an engine that no longer matches the disk.
            log.warning("policy directory changed during write; reloading from disk instead")
            await compiled.discard()
            await svc.reload_locked("file")
            return
        await svc.swap(compiled, texts, attribution)
