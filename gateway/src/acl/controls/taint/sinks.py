"""Shared IFC helpers for the taint family: tool labels → label updates, and sink detection for a concrete call."""

from __future__ import annotations

import shlex
from collections.abc import Iterable
from typing import Any

from acl.contracts.common import DATA_CLASS_ORDER, Capability, DataClass, TaintFlag, ToolLabel
from acl.contracts.decision import LabelUpdate
from acl.contracts.inspection import ToolCallPayload
from acl.controls.normalise.intent import COMMAND_KEYS
from acl.controls.tools.catalogue import is_sink_tool
from acl.controls.tools.commands import analyze_command
from acl.policy.models import ToolDef


def labels_for_tool(tool: ToolDef | None, *, unknown_untrusted: bool = True) -> LabelUpdate | None:
    """What the output of a tool does to the session labels (concept §9 "Tool results are untrusted").

    * `reads_untrusted`, or a tool that is not in the catalogue → integrity untrusted;
    * `touches_sensitive` → confidentiality confidential + `sensitive` taint.
    """
    if tool is None:
        return LabelUpdate(integrity_untrusted=True) if unknown_untrusted else None
    untrusted = ToolLabel.reads_untrusted in tool.labels
    sensitive = ToolLabel.touches_sensitive in tool.labels
    if not (untrusted or sensitive):
        return None
    return LabelUpdate(
        integrity_untrusted=untrusted,
        confidentiality=DataClass.confidential if sensitive else None,
        taint=[TaintFlag.sensitive.value] if sensitive else [],
    )


def merge_updates(updates: Iterable[LabelUpdate | None]) -> LabelUpdate | None:
    """Monotonic join of label updates."""
    merged = LabelUpdate()
    seen = False
    for u in updates:
        if u is None:
            continue
        seen = True
        merged.integrity_untrusted = merged.integrity_untrusted or u.integrity_untrusted
        if u.confidentiality and (
            merged.confidentiality is None
            or DATA_CLASS_ORDER[u.confidentiality] > DATA_CLASS_ORDER[merged.confidentiality]
        ):
            merged.confidentiality = u.confidentiality
        merged.taint = list(dict.fromkeys([*merged.taint, *u.taint]))
    return merged if seen else None


def command_values(tool: ToolDef, payload: ToolCallPayload) -> list[str]:
    """Shell command strings of a call: declared `command` checker fields plus command-like aliases (`cmd`, ...)."""
    out: list[str] = []
    declared = [c for c in tool.checkers if c.type == "command"]
    for checker in declared:
        out.extend(_strings(payload.arguments.get(checker.field.split(".")[0])))
    if declared or Capability.exec in tool.capabilities:
        for key, value in payload.arguments.items():
            if key.lower() in COMMAND_KEYS:
                out.extend(v for v in _strings(value) if v not in out)
    return out


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return [shlex.join(value)]
    return []


def call_is_sink(tool: ToolDef | None, payload: ToolCallPayload) -> tuple[bool, str]:
    """Is this concrete call an external-egress sink? (label, unknown tool, or a shell command that sends/publishes)"""
    if tool is None:
        return True, "tool is not in the catalogue (treated as a sink)"
    if is_sink_tool(tool):
        return True, "tool is labelled external_egress"
    for command in command_values(tool, payload):
        analysis = analyze_command(command, cwd=payload.cwd, root=payload.workspace_root)
        if analysis.egress:
            return True, "shell command sends data out or publishes"
    return False, ""
