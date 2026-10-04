"""Typed approval fields for the admin API (approver label, data class, client, red flags, preview, why-held lines).

Everything here is derived from data the gateway already holds and has redacted: the held verdicts (reasons and
finding *types*, never values), the session labels, the tool catalogue labels and the redacted preview text. The result
is stored in `ApprovalRow.detail` when the approval is created, so the admin API reads it back without recomputing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from acl.contracts.admin import ApprovalPreview
from acl.contracts.common import DATA_CLASS_ORDER, Action, DataClass, Integrity, TaintFlag, ToolLabel
from acl.contracts.decision import Decision, Verdict
from acl.contracts.inspection import InspectionContext

APPROVER_LABELS = {
    "admin": "Security team",
    "security": "Security team",
    "user": "Team lead",
    "team_lead": "Team lead",
}
_GENERIC_APPS = frozenset({"", "unknown", "agent", "sdk"})
_FLOW_RULE = "SEC-FLOW-01"
_FINDING_FLAGS = {
    "CMD_OUTSIDE_WORKSPACE": "outside workspace",
    "CMD_UNTRUSTED_EXEC": "runs code after untrusted input",
    "CMD_PRIVILEGE_ESCALATION": "privilege escalation",
    "CMD_PIPE_TO_INTERPRETER": "pipes a download into a shell",
    "PACKAGE_UNVERIFIABLE": "unverified package",
}
_DIFF_HUNK = re.compile(r"^(@@ .* @@|\+\+\+ \S|--- (a/|/dev/null))", re.MULTILINE)
_PLAN_SUMMARY = re.compile(r"\d+ to add, \d+ to change, \d+ to destroy", re.IGNORECASE)


def approver_label(scope: str) -> str | None:
    return APPROVER_LABELS.get(scope)


def holding_verdicts(decision: Decision, shadow_ids: Iterable[str] = ()) -> list[Verdict]:
    """Enforced verdicts that asked for approval (shadow controls never hold a call)."""
    shadow = set(shadow_ids)
    return [v for v in decision.verdicts if v.action == Action.require_approval and v.control_id not in shadow]


def reasons_of(holders: list[Verdict]) -> list[str]:
    """One line per distinct reason of the holding controls (verdict reasons carry no raw values by contract)."""
    out: list[str] = []
    for v in holders:
        for part in (v.reason or "").split("; "):
            text = part.strip()[:300]
            if text and text not in out:
                out.append(text)
    return out[:10]


def client_of(ctx: InspectionContext) -> str | None:
    app = (ctx.client.app or "").strip().lower()
    agent = ctx.principal.agent_id
    client = agent if agent and app in _GENERIC_APPS else (app or agent or "")
    return client if client and client not in _GENERIC_APPS else None


def data_class_of(decision: Decision, ctx: InspectionContext) -> str:
    labels = decision.labels_after
    level = max((labels.confidentiality, ctx.session.labels.confidentiality), key=lambda c: DATA_CLASS_ORDER[c])
    return level.value


def flags_of(
    decision: Decision,
    ctx: InspectionContext,
    holders: list[Verdict],
    *,
    egress: bool,
    tool_labels: Iterable[ToolLabel] = (),
) -> list[str]:
    """Red flags a reviewer should see first. Deterministic, from labels / rule ids / finding types only."""
    flags: list[str] = []

    def add(flag: str) -> None:
        if flag not in flags:
            flags.append(flag)

    holder_ids = {v.control_id for v in holders}
    labels = decision.labels_after
    held_by_flow = any(_FLOW_RULE in v.rule_ids for v in holders) or any(_FLOW_RULE in r for r in decision.rule_ids)
    if held_by_flow:
        if labels.integrity == Integrity.untrusted or TaintFlag.untrusted in labels.taint:
            add("untrusted input")
        if (
            TaintFlag.sensitive in labels.taint
            or DATA_CLASS_ORDER[labels.confidentiality] >= DATA_CLASS_ORDER[DataClass.confidential]
        ):
            add("sensitive data")
    if egress or ToolLabel.external_egress in set(tool_labels):
        add("external egress")
    if ToolLabel.irreversible in set(tool_labels):
        add("irreversible")
    for v in decision.verdicts:
        if v.control_type == "secrets" and v.findings:
            add("secret in arguments")
        elif v.control_type == "pii" and v.findings:
            add("personal data")
        if v.control_id in holder_ids:
            for f in v.findings:
                if (label := _FINDING_FLAGS.get(f.entity_type)) is not None:
                    add(label)
    return flags


def preview_of(tool: str | None, text: str) -> ApprovalPreview | None:
    """Typed view of the (already redacted) preview text: e-mail for mail tools, diff when it holds diff hunks,
    plan for a Terraform plan summary, else plain text."""
    body = text.strip("\n")
    if not body:
        return None
    name = (tool or "").lower()
    kind: Any = "text"
    if name.startswith(("email", "mail")) or ".mail" in name or name.endswith((".send_email", "_email")):
        kind = "email"
    elif _DIFF_HUNK.search(body):
        kind = "diff"
    elif _PLAN_SUMMARY.search(body):
        kind = "plan"
    return ApprovalPreview(type=kind, body=body)
