"""Wiring for the PII control: the session pseudonymisation vault as a `control_deps` service."""

from __future__ import annotations

import os

from fastapi import FastAPI

from acl.controls.pii.vault import PseudonymVault
from acl.settings import Settings


def install(app: FastAPI, settings: Settings) -> None:
    deps = app.state.control_deps
    if deps.get("settings") is None:
        deps.register("settings", settings)  # value-hash salt for findings
    if deps.get("vault") is None:
        ttl = float(os.environ.get("ACL_VAULT_TTL_S", "3600"))
        vault = PseudonymVault(ttl_s=ttl)
        deps.register("vault", vault)
        app.state.vault = vault
