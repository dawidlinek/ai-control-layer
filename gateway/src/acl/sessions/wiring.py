from __future__ import annotations

from fastapi import FastAPI

from acl.sessions.store import InMemorySessionStore
from acl.settings import Settings


def install(app: FastAPI, settings: Settings) -> None:
    store = InMemorySessionStore()
    app.state.sessions = store
    app.state.control_deps.register("sessions", store)
    if not hasattr(app.state, "flow_hooks"):
        app.state.flow_hooks = []
