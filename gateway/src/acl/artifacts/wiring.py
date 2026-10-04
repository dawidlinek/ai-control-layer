"""Installer for the model-artifact scanner (listed in `acl.main.INSTALLERS` before the policy installer).

Provides on the app:
    app.state.artifacts            ArtifactStore (scan results; also control service "artifacts")
    app.state.connectors.artifact_gate   registry hook: a model with an `artifact:` ref is only available while the
                                         newest scan of that sha256 passed (consulted per request)

The `/admin/v1/artifacts*` routes live in `acl.api.admin.artifacts`; SEC-ART-01 (`artifact_scan`) registers through
`acl.controls.artifacts`.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from acl.artifacts.store import ArtifactStore
from acl.policy.models import ModelEntry
from acl.settings import Settings

log = logging.getLogger(__name__)


def install(app: FastAPI, settings: Settings) -> None:
    store = ArtifactStore(lambda: app.state.db)
    app.state.artifacts = store
    app.state.control_deps.register("artifacts", store)

    async def load(_app: FastAPI) -> None:
        try:
            await store.load()
        except Exception:  # an unreadable table must not stop the gateway; gated models stay unavailable
            log.exception("artifact scan index could not be loaded")

    app.state.on_startup.append(load)

    def gate(entry: ModelEntry) -> str | None:
        return store.gate_problem(entry.artifact)

    connectors = getattr(app.state, "connectors", None)
    if connectors is not None:
        connectors.artifact_gate = gate
