"""Installer for approvals (listed in `acl.main.INSTALLERS` before the policy installer).

Provides on the app:
    app.state.approvals         ApprovalService (also control service "approvals"; SEC-TOOL-01 reads elevations)
    app.state.bypass_detector   BypassDetector, registered in `app.state.flow_hooks` (plugin-bypass incidents)

The `/v1/decide` + `/v1/approvals/*` and `/admin/v1/approvals*` routes live in `acl.api.decide` and
`acl.api.admin.approvals`; they are already mounted by `create_app`.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI

from acl.approvals.bypass import BypassDetector
from acl.approvals.db_models import ApprovalRow
from acl.approvals.service import ApprovalService
from acl.contracts.common import Integrity, TaintFlag
from acl.contracts.inspection import SessionLabels
from acl.controls.normalise.scan import value_salt
from acl.controls.taint.sinks import labels_for_tool
from acl.sessions.store import merge_labels
from acl.settings import Settings

log = logging.getLogger(__name__)


def install(app: FastAPI, settings: Settings) -> None:
    def policy() -> Any:
        engine = getattr(app.state, "engine", None)
        return None if engine is None else engine.policy

    def shadow() -> list[str]:
        engine = getattr(app.state, "engine", None)
        return [] if engine is None else [c.id for c in engine.pipeline.controls if c.shadow]

    def salt() -> str:
        """The audit sink's salt (settings), so `args_hash` here equals `args_hash` in the decision record."""
        raw = getattr(settings, "value_hash_salt", None)
        return raw.get_secret_value() if hasattr(raw, "get_secret_value") else value_salt(app.state.control_deps)

    service = ApprovalService(
        lambda: app.state.db,
        lambda: getattr(app.state, "audit", None),
        salt=salt,
        policy_view=policy,
        shadow_view=shadow,
    )

    async def after_approve(row: ApprovalRow) -> None:
        """An approved call will run: its labels (tool output, egress) now reach the session (monotonic)."""
        sessions = getattr(app.state, "sessions", None)
        pol = policy()
        if sessions is None or pol is None or not row.tool:
            return
        tool = pol.tools.get(row.tool)  # type: ignore[call-overload]
        upd = labels_for_tool(tool, unknown_untrusted=False)
        raised = SessionLabels()
        if upd is not None:
            if upd.integrity_untrusted:
                raised.integrity = Integrity.untrusted
                raised.taint.append(TaintFlag.untrusted)
            if upd.confidentiality:
                raised.confidentiality = upd.confidentiality
            raised.taint.extend(TaintFlag(t) for t in upd.taint if t in TaintFlag.__members__.values())
        if row.egress:
            raised.taint.append(TaintFlag.egress_used)
        if upd is None and not row.egress:
            return
        raised.taint = list(dict.fromkeys(raised.taint))
        raised.sources = ["SEC-TAINT-01"]
        await sessions.update(
            row.session_id, lambda state: state.model_copy(update={"labels": merge_labels(state.labels, raised)})
        )

    service.after_approve = after_approve
    detector = BypassDetector(app, salt=salt)
    app.state.approvals = service
    app.state.bypass_detector = detector
    app.state.control_deps.register("approvals", service)
    if not hasattr(app.state, "flow_hooks"):
        app.state.flow_hooks = []
    app.state.flow_hooks.append(detector)
