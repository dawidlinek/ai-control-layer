"""Plain-language narration of audit events: deterministic templates, never an LLM.

The panel shows one sentence per event ("Anna Nowak's prompt contained a PESEL, an IBAN and a name. They were
replaced with placeholders before the model saw them."), the steps that changed something, and the full decision
timeline. Everything here is filled from the audit record and uses only entity types and counts, tool names, model
ids, rule ids, usernames and times: never a raw value (CLAUDE.md rule 2). Each sentence is a template per rule family
and decision type, so it is always true, testable and translatable.
"""

from __future__ import annotations

import contextlib
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from acl.contracts.admin import TraceControl, TraceStep
from acl.contracts.audit import AuditEvent, AuditFinding, AuditVerdict, EventType
from acl.contracts.common import DATA_CLASS_ORDER, Action, AuthMethod, ConnectorTier, DataClass, InspectionPoint, Phase

if TYPE_CHECKING:
    from acl.policy.models import Policy

_CONTENT_ACTIONS = (Action.pseudonymise, Action.redact, Action.sanitize)
_SENSITIVE = (DataClass.confidential, DataClass.restricted)

# ---------------------------------------------------------------- small helpers


def hhmm(dt: datetime) -> str:
    """`14:03 UTC`."""
    return (dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)).strftime("%H:%M UTC")


def display_name(event: AuditEvent) -> str:
    p = event.principal
    if p is None:
        return "Someone"
    return p.username or p.agent_id or p.subject


def _poss(name: str) -> str:
    return f"{name}'" if name.endswith("s") else f"{name}'s"


def _lead_lower(text: str) -> str:
    return text[0].lower() + text[1:] if text.startswith(("The ", "A ")) else text


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


_ENTITY_NAMES = {
    "PESEL": "PESEL",
    "IBAN": "IBAN",
    "NIP": "NIP",
    "REGON": "REGON",
    "PERSON": "name",
    "PER": "name",
    "NAME": "name",
    "EMAIL": "e-mail address",
    "EMAIL_ADDRESS": "e-mail address",
    "PHONE": "phone number",
    "PHONE_NUMBER": "phone number",
    "ADDRESS": "address",
    "CREDIT_CARD": "card number",
    "ID_CARD": "ID card number",
    "PASSPORT": "passport number",
    "DATE_OF_BIRTH": "date of birth",
    "ORG": "organisation name",
    "LOCATION": "location",
    "API_KEY": "API key",
    "PRIVATE_KEY": "private key",
    "PASSWORD": "password",
    "JWT": "token",
    "INJECTION": "injected instruction",
    "MARKDOWN_IMAGE": "hidden image link",
    "GITHUB_TOKEN": "GitHub token",
}


_ACRONYMS = frozenset(
    {"AWS", "API", "SSH", "JWT", "URL", "PII", "ID", "IP", "GCP", "SQL", "RSA", "PGP", "IBAN", "PESEL"}
)


def entity_name(entity: str) -> str:
    known = _ENTITY_NAMES.get(entity.upper())
    if known:
        return known
    words = entity.replace("-", "_").split("_")
    return " ".join(w.upper() if w.upper() in _ACRONYMS else w.lower() for w in words if w)


def _article(phrase: str) -> str:
    return "an" if phrase[:1].lower() in "aeiou" else "a"


def _plural(name: str) -> str:
    return name + "s"


def _entities_phrase(entities: Counter[str]) -> str:
    parts = []
    for entity, n in entities.items():
        name = entity_name(entity)
        parts.append(f"{_article(name)} {name}" if n == 1 else f"{n} {_plural(name)}")
    return _join(parts)


def _unique_findings(verdicts: list[AuditVerdict]) -> list[AuditFinding]:
    seen: set[tuple[str, int | None, int | None, str]] = set()
    out: list[AuditFinding] = []
    for v in verdicts:
        for f in v.findings:
            key = (f.field, f.start, f.end, f.entity_type)
            if f.start is None or key not in seen:
                seen.add(key)
                out.append(f)
    return out


def _entity_types(verdicts: list[AuditVerdict]) -> list[str]:
    return list(dict.fromkeys(f.entity_type for v in verdicts for f in v.findings))


# ---------------------------------------------------------------- rule families

_FAMILIES: tuple[tuple[str, str], ...] = (
    ("SEC-PII", "pii"),
    ("SEC-NER", "pii"),
    ("SEC-SECRET", "secret"),
    ("SEC-PI-", "injection"),
    ("SEC-SIM", "injection"),
    ("SEC-JUDGE-SAN", "injection"),
    ("SEC-FLOW", "flow"),
    ("SEC-TAINT", "flow"),
    ("SEC-TOOL", "tool"),
    ("AUTHZ", "tool"),
    ("SEC-EXFIL", "exfil"),
    ("SEC-MCP", "mcp"),
    ("SEC-SIG", "signature"),
    ("SIG-", "signature"),
    ("FEED-", "signature"),
    ("SEC-BUDGET", "budget"),
    ("BUDGET-", "budget"),
    ("SEC-LOOP", "loop"),
    ("SEC-MODEL", "model"),
    ("SEC-SESSION", "session"),
    ("LOCK-", "lock"),
    ("SEC-SAFE", "safety"),
    ("SEC-HYG", "hygiene"),
    ("SEC-JUDGE", "judge"),
    ("SEC-PLAN", "judge"),
    ("SEC-DECIDE", "risk"),
)

_FAMILY_LABEL = {
    "pii": "personal-data check",
    "secret": "secret check",
    "injection": "prompt-injection check",
    "flow": "Rule of Two check",
    "tool": "tool policy",
    "exfil": "data-exfiltration check",
    "mcp": "MCP check",
    "signature": "known-threat feed",
    "budget": "budget limit",
    "loop": "loop detector",
    "model": "model access rule",
    "session": "session label rule",
    "lock": "organisation rule",
    "safety": "content-safety check",
    "hygiene": "output check",
    "judge": "judge check",
    "risk": "risk score",
}

_SIG_KIND = {
    "PKG": "a known-bad package",
    "IOC": "a known malicious address",
    "CMD": "a dangerous command",
    "URL": "a known-exploited URL",
    "FILE": "a known malicious file",
    "PATH": "a protected path",
    "ARG": "a suspicious argument",
    "CODE": "dangerous code",
    "FLAG": "a dangerous option",
    "MD": "a data-leaking link",
    "SKILL": "a fake skill prerequisite",
    "INJ": "a known prompt-injection text",
    "MCP": "a poisoned MCP tool description",
}

_POINT_NOUN = {
    InspectionPoint.ingress: "prompt",
    InspectionPoint.egress: "answer",
    InspectionPoint.tool_call: "tool call",
    InspectionPoint.tool_result: "tool result",
    InspectionPoint.embeddings: "embedding request",
    InspectionPoint.agent_message: "agent message",
    InspectionPoint.artifact_load: "model file",
    InspectionPoint.mcp_initialize: "MCP connection",
    InspectionPoint.mcp_tools_list: "tool list",
}


def family_of(rule_id: str | None) -> str | None:
    if not rule_id:
        return None
    for prefix, family in _FAMILIES:
        if rule_id.startswith(prefix):
            return family
    return None


def _suffix(rule_ids: list[str]) -> str:
    for rid in rule_ids:
        if "." in rid:
            return rid.split(".", 1)[1]
    return ""


class _Ctx:
    """Everything a sentence template needs, derived once from the event."""

    def __init__(self, event: AuditEvent, policy: Policy | None) -> None:
        d = event.decision
        assert d is not None
        self.event = event
        self.d = d
        self.policy = policy
        self.name = display_name(event)
        self.poss = _poss(self.name)
        self.point = event.point
        self.what = _POINT_NOUN.get(event.point, "request") if event.point else "request"
        self.tool = event.tool or "a tool"
        self.server = event.server or "an MCP server"
        self.route = event.route
        ids = ([d.decided_by] if d.decided_by else []) + list(d.rule_ids)
        self.fam: str | None = None
        self.rid: str | None = d.rule_ids[0] if d.rule_ids else None
        for rid in ids:
            fam = family_of(rid)
            if fam:
                self.fam, self.rid = fam, (rid if rid in d.rule_ids else self.rid)
                break
        self.suffix = _suffix(list(d.rule_ids))
        self.applied = list(d.applied)
        self.data_class = self._data_class()

    def _data_class(self) -> DataClass | None:
        found: list[DataClass] = []
        if self.event.labels_after is not None:
            found.append(self.event.labels_after.confidentiality)
        if self.route is not None:
            with contextlib.suppress(ValueError):
                found.append(DataClass(str(self.route.factors.get("data_class"))))
        return max(found, key=lambda c: DATA_CLASS_ORDER[c]) if found else None

    def family_verdicts(self) -> list[AuditVerdict]:
        picked = [
            v for v in self.event.verdicts if v.action != Action.allow and family_of(v.control_id) == self.fam
        ] or [v for v in self.event.verdicts if v.action != Action.allow]
        return picked

    def entities(self) -> Counter[str]:
        return Counter(f.entity_type for f in _unique_findings(self.family_verdicts()))

    @property
    def np(self) -> str:
        """Subject noun phrase, e.g. `Anna's prompt`, `The answer to Anna`."""
        p = self.point
        if p == InspectionPoint.ingress:
            return f"{self.poss} prompt"
        if p == InspectionPoint.egress:
            return f"The answer to {self.name}"
        if p == InspectionPoint.tool_call:
            return f"{self.poss} {self.tool} call" if self.event.tool else f"{self.poss} tool call"
        if p == InspectionPoint.tool_result:
            return f"The {self.tool} result for {self.name}" if self.event.tool else f"A tool result for {self.name}"
        if p == InspectionPoint.embeddings:
            return f"{self.poss} embedding request"
        if p == InspectionPoint.mcp_tools_list:
            return f"The tool list from {self.server}"
        if p == InspectionPoint.mcp_initialize:
            return f"The connection to {self.server}"
        if p == InspectionPoint.artifact_load:
            return "The model file"
        return f"{self.poss} {self.what}"

    def before(self, plural: bool) -> str:
        them = "them" if plural else "it"
        if self.point == InspectionPoint.egress:
            return "the answer was delivered"
        if self.point == InspectionPoint.tool_call:
            return "the tool ran"
        return f"the model saw {them}"


# ---------------------------------------------------------------- sentence templates


def _h_content(c: _Ctx, a: Action) -> str | None:
    """PII / secrets: found entity types, then what was done to them."""
    ents = c.entities()
    total = sum(ents.values())
    phrase = _entities_phrase(ents) or ("a secret" if c.fam == "secret" else "personal data")
    plural = total > 1
    they = "They were" if plural else "It was"
    if a == Action.pseudonymise:
        what = "placeholders" if plural else "a placeholder"
        return f"{c.np} contained {phrase}. {they} replaced with {what} before {c.before(plural)}."
    if a in (Action.redact, Action.sanitize):
        return f"{c.np} contained {phrase}. {they} removed before {c.before(plural)}."
    if a == Action.block:
        tail = "so the secret is never passed on" if c.fam == "secret" else "which policy does not let through"
        return f"{c.np} contained {phrase}, {tail}. It was blocked."
    if a == Action.require_approval:
        return f"{c.np} contained {phrase} and is waiting for a person's approval."
    if a == Action.route_local:
        return f"{c.np} contained {phrase}, so the request stayed on a local model."
    return None


def _h_injection(c: _Ctx, a: Action) -> str | None:
    if c.point == InspectionPoint.tool_result:
        lead = f"The {c.tool} result for {c.name} looked like it contained instructions aimed at the agent."
    elif c.point == InspectionPoint.ingress:
        lead = f"{c.np} looked like an attempt to override the model's instructions."
    else:
        lead = f"{c.np} looked like it contained injected instructions."
    tails = {
        Action.sanitize: "The injected part was removed and the rest passed on.",
        Action.redact: "The injected part was removed and the rest passed on.",
        Action.block: "It was blocked.",
        Action.require_approval: "It is waiting for a person to review it.",
        Action.route_local: "The request stayed on a local model.",
    }
    tail = tails.get(a)
    return f"{lead} {tail}" if tail else None


def _approver(c: _Ctx) -> str:
    ap = c.event.approval
    if ap is None:
        return ""
    who = "the security team" if ap.approver_scope == "admin" else "their team lead"
    return f" from {who}"


def _h_flow(c: _Ctx, a: Action) -> str | None:
    lead = f"{c.poss} agent tried to run {c.tool}"
    if c.suffix == "TAINT_FULL":
        why = "after reading untrusted content, which this preset never lets reach an outside action"
    else:
        why = "after reading untrusted content and handling sensitive data (the Rule of Two)"
    if a == Action.require_approval:
        return f"{lead} {why}. It is waiting for approval{_approver(c)}."
    if a == Action.block:
        return f"{lead} {why}. The call was blocked."
    return None


def _h_tool(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        why = {
            "UNKNOWN_TOOL": "which Rogatka does not know",
            "CONFINED": "which this session is no longer allowed to use",
            "BYPASS": "by working around a restriction",
        }.get(c.suffix, "but that is not allowed for them")
        sep = " " if c.suffix == "BYPASS" else ", "
        return f"{c.name} tried to use {c.tool}{sep}{why}. The call was blocked before it ran."
    if a == Action.require_approval:
        return f"{c.poss} call to {c.tool} needs approval before it can run."
    return None


def _h_exfil(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        return f"{c.np} contained a link that could send data to an outside address. It was blocked."
    if a in (Action.redact, Action.sanitize):
        return f"{c.np} contained a link that could leak data, such as a hidden image. The link was removed."
    return None


def _h_mcp(c: _Ctx, a: Action) -> str | None:
    if c.rid and c.rid.startswith("SEC-MCP-02"):
        return f"The connection to {c.server} broke an MCP protocol rule and was {_blocked(a)}."
    kinds = set(_entity_types(c.event.verdicts))
    if "MCP_TOOL_POISONED" in kinds or "MCP_TOOL_HIDDEN_CHARS" in kinds:
        what = f"A tool description from {c.server} contained hidden instructions."
    else:
        what = f"The {c.server} MCP server changed a tool description after it was approved."
    if a == Action.block:
        return f"{what} The tool was quarantined and an incident was opened."
    if a == Action.require_approval:
        return f"{what} The tool is waiting for approval."
    return None


def _blocked(a: Action) -> str:
    return "blocked" if a == Action.block else "held for approval" if a == Action.require_approval else "stopped"


def sig_kind(rule_id: str) -> str:
    rest = rule_id.split("-", 1)[1] if "-" in rule_id else ""
    return _SIG_KIND.get(rest.split("-", 1)[0], "a known threat")


def _h_signature(c: _Ctx, a: Action) -> str | None:
    sig_ids = [r for r in c.d.rule_ids if family_of(r) == "signature" and not r.startswith("SEC-SIG")]
    rid = sig_ids[0] if sig_ids else c.rid
    kind = sig_kind(rid) if rid and not rid.startswith("SEC-SIG") else "a known threat"
    more = f" and {len(sig_ids) - 1} more" if len(sig_ids) > 1 else ""
    lead = f"{c.np} matched {kind} on the known-threat list ({rid}{more})."
    tails = {
        Action.block: "It was blocked.",
        Action.require_approval: "It is waiting for a person's approval.",
        Action.redact: "The matching part was removed.",
        Action.sanitize: "The matching part was removed.",
        Action.route_local: "The request stayed on a local model.",
    }
    tail = tails.get(a)
    return f"{lead} {tail}" if tail else None


def _h_budget(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        if c.suffix == "BREAKER":
            return f"The circuit breaker on {c.poss} budget is open, so the {c.what} was blocked until it cools down."
        return f"{c.name} reached a spending or usage limit, so the {c.what} was blocked."
    if a in (Action.route_local, Action.downgrade):
        return f"{c.poss} budget is used up, so the request was served by a local model instead."
    return None


def _h_loop(c: _Ctx, a: Action) -> str | None:
    texts = {
        "REPEAT": f"{c.poss} agent repeated {c.tool} with the same arguments several times in a short while.",
        "NO_PROGRESS": f"{c.poss} agent kept repeating {c.tool} without making progress.",
        "DEPTH": f"{c.poss} agent nested tool calls deeper than the limit allows.",
        "STEPS": f"{c.poss} agent reached the step limit for a session.",
    }
    if a == Action.block:
        lead = texts.get(c.suffix, f"{c.poss} agent looped.")
        return f"{lead} The loop detector blocked it."
    if a == Action.require_approval:
        return f"{c.poss} session suddenly used far more tokens than usual, so the request is waiting for approval."
    return None


def _h_model(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        asked = (c.event.model_requested or c.event.model or "a model")[:60]
        return (
            f"{c.name} asked for {asked}, which they are not allowed to use. "
            "The request was blocked and an incident was opened."
        )
    return None


def _h_session(c: _Ctx, a: Action) -> str | None:
    if a != Action.route_local:
        return None
    dc = c.data_class.value if c.data_class in _SENSITIVE and c.data_class else "confidential"
    labels = c.event.labels_after
    since = f" since {hhmm(labels.since)}" if labels is not None and labels.since is not None else ""
    return f"This session is {dc}{since}, so the request stayed on local models."


def _h_lock(c: _Ctx, a: Action) -> str | None:
    if a != Action.route_local:
        return None
    dc = c.data_class.value if c.data_class else "sensitive"
    return f"The data is {dc}, so the request stayed on a local model (organisation rule {c.rid})."


def _h_safety(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        return f"The content-safety check blocked the {c.what} for {c.name}."
    if a in _CONTENT_ACTIONS:
        return f"The content-safety check changed the {c.what} for {c.name}."
    return None


def _h_hygiene(c: _Ctx, a: Action) -> str | None:
    if a == Action.block:
        return f"The output check blocked the answer to {c.name}."
    if a in _CONTENT_ACTIONS:
        return f"The output check cleaned the answer to {c.name} before it was delivered."
    return None


def _h_judge(c: _Ctx, a: Action) -> str | None:
    rid = c.rid or ""
    if "ALIGN" in rid:
        why = "did not match the user's task"
    elif "-CI-" in rid:
        why = "would share information outside the context it came from"
    elif "PLAN" in rid:
        why = "was not part of the approved task plan"
    else:
        why = "was judged risky"
    if a == Action.block:
        return f"A judge model decided {c.poss} {c.tool} call {why}. It was blocked."
    if a == Action.require_approval:
        return f"A judge model decided {c.poss} {c.tool} call {why}. It is waiting for approval."
    return None


_HANDLERS = {
    "pii": _h_content,
    "secret": _h_content,
    "injection": _h_injection,
    "flow": _h_flow,
    "tool": _h_tool,
    "exfil": _h_exfil,
    "mcp": _h_mcp,
    "signature": _h_signature,
    "budget": _h_budget,
    "loop": _h_loop,
    "model": _h_model,
    "session": _h_session,
    "lock": _h_lock,
    "safety": _h_safety,
    "hygiene": _h_hygiene,
    "judge": _h_judge,
}
_ROUTING_FAMILIES = {"session", "lock", "budget"}


def _generic(c: _Ctx, a: Action) -> str:
    via = f" ({c.rid})" if c.rid else ""
    if a == Action.block:
        return f"{c.np} was blocked by {'rule ' + c.rid if c.rid else 'policy'}."
    if a == Action.require_approval:
        return f"{c.np} is waiting for a person's approval{via}."
    if a == Action.redact:
        return f"Parts of {_lead_lower(c.np)} were removed{via}."
    if a == Action.pseudonymise:
        return f"Parts of {_lead_lower(c.np)} were replaced with placeholders{via}."
    if a == Action.sanitize:
        return f"{c.np} was cleaned before it went on{via}."
    if a == Action.route_local:
        return f"{c.poss} request stayed on a local model{via}."
    if a == Action.downgrade:
        return f"{c.poss} request was served by a more restricted model{via}."
    if a == Action.monitor:
        return f"{c.np} was flagged{via} but only logged."
    return f"{c.np} was allowed."


def _allow(c: _Ctx) -> str:
    model = c.event.model
    p = c.point
    if p == InspectionPoint.ingress:
        return f"{c.poss} prompt went to {model} unchanged." if model else f"{c.poss} prompt was allowed."
    if p == InspectionPoint.egress:
        src = f" from {model}" if model else ""
        return f"The answer{src} to {c.name} passed the output checks unchanged."
    if p == InspectionPoint.embeddings:
        return f"{c.poss} embedding request went to {model} unchanged." if model else f"{c.np} was allowed."
    if p == InspectionPoint.tool_call:
        return f"{c.poss} {c.tool} call was allowed."
    if p == InspectionPoint.tool_result:
        return f"{c.np} passed the checks unchanged."
    return f"{c.np} was allowed."


def _local_clause(c: _Ctx) -> str:
    because = f" because the data is {c.data_class.value}" if c.data_class in _SENSITIVE and c.data_class else ""
    return f"the request stayed on a local model{because}"


def _system_sentence(event: AuditEvent) -> str:
    who = display_name(event) if event.principal else "An administrator"
    detail = event.detail or {}
    t = event.event_type
    if t == EventType.system_alert and detail.get("event") == "kill_switch":
        state = "engaged" if detail.get("engaged") else "released"
        return f"{who} {state} the kill switch for connector {detail.get('connector', 'unknown')}."
    texts = {
        EventType.policy_change: f"{who} changed the policy.",
        EventType.policy_reload_failed: "A policy reload failed; the last good version stays active.",
        EventType.grant_change: f"{who} changed access grants.",
        EventType.incident: "An incident was opened or updated.",
        EventType.approval: "An approval request was updated.",
        EventType.breakglass: f"{who} viewed raw content with break-glass access.",
        EventType.feed_update: "The known-threat feed was updated.",
        EventType.feed_verify_failed: "The known-threat feed failed verification and was ignored.",
        EventType.artifact_scan: "A model file was scanned.",
        EventType.mcp_drift: "An MCP tool description changed.",
        EventType.budget_breach: "A budget limit was reached.",
        EventType.auth_failure: "A sign-in attempt failed.",
        EventType.system_alert: "A system alert was raised.",
    }
    return texts.get(t, f"{t.value.replace('_', ' ').capitalize()} was recorded.")


def summary(event: AuditEvent, policy: Policy | None = None) -> str:
    """One plain-language sentence for the event (templates only; no raw values)."""
    d = event.decision
    if event.event_type != EventType.decision or d is None:
        return _system_sentence(event)
    c = _Ctx(event, policy)
    action = d.action
    if action == Action.monitor and d.would_action is not None:
        label = _FAMILY_LABEL.get(c.fam or "", "policy check")
        out = (
            f"The {label} flagged {_lead_lower(c.np)}. Monitor mode: it was logged, not enforced "
            f"(it would have been {d.would_action.value})."
        )
    else:
        primary = action
        if primary == Action.allow and c.applied:
            primary = c.applied[0]
        if primary == Action.allow:
            out = _allow(c)
        else:
            handler = _HANDLERS.get(c.fam or "")
            out = (handler(c, primary) if handler else None) or _generic(c, primary)
            if Action.route_local in c.applied and primary in _CONTENT_ACTIONS and c.fam not in _ROUTING_FAMILIES:
                out = out[:-1] + f", and {_local_clause(c)}."
    if event.route is not None and event.route.degraded and event.point == InspectionPoint.ingress:
        out += " The preferred model was unavailable, so a local fallback answered."
    return out


# ---------------------------------------------------------------- trace steps

_PHASE_STEP: dict[Phase, str] = {
    Phase.normalise: "normalise",
    Phase.deterministic: "rules",
    Phase.similarity: "similarity",
    Phase.semantic_l1: "classifier",
    Phase.semantic_l2: "judge",
    Phase.decide: "decide",
    Phase.egress_hygiene: "output",
}


def _trace_control(v: AuditVerdict) -> TraceControl:
    return TraceControl(
        control_id=v.control_id,
        control_type=v.control_type,
        action=v.action,
        rule_ids=list(v.rule_ids),
        score=v.score,
        status=v.status.value,
        latency_ms=v.latency_ms,
        findings=_entity_types([v]),
        reason=v.reason,
    )


def _vphrase(v: AuditVerdict) -> str:
    rid = v.rule_ids[0] if v.rule_ids else v.control_id
    ents = Counter(f.entity_type for f in _unique_findings([v]))
    score = f" (score {v.score:.2f})" if v.score is not None else ""
    if ents:
        return f"{rid} found {_entities_phrase(ents)}{score} → {v.action.value}"
    return f"{rid}{score} → {v.action.value}"


def _verdict_step(step: str, verdicts: list[AuditVerdict], *, none: str, passed: str, joiner: str = "; ") -> TraceStep:
    if not verdicts:
        return TraceStep(step=step, result=none)  # type: ignore[arg-type]
    hits = [v for v in verdicts if v.action != Action.allow]
    ms = round(sum(v.latency_ms for v in verdicts), 3)
    if hits:
        result = joiner.join(_vphrase(v) for v in hits)
    else:
        scores = [v.score for v in verdicts if v.score is not None]
        top = f" (highest score {max(scores):.2f})" if scores else ""
        result = passed.format(n=len(verdicts)) + top
    return TraceStep(
        step=step,  # type: ignore[arg-type]
        result=result,
        ms=ms,
        changed=bool(hits),
        controls=[_trace_control(v) for v in verdicts],
    )


def _decide_step(event: AuditEvent) -> TraceStep:
    d = event.decision
    assert d is not None
    controls = [_trace_control(v) for v in event.verdicts if v.phase == Phase.decide]
    if d.action == Action.monitor and d.would_action is not None:
        result = f"monitor mode: logged only (would be {d.would_action.value})"
    elif d.action == Action.allow and not d.applied:
        result = "allow: no control objected"
    else:
        shown = " + ".join(a.value for a in d.applied) if d.applied else d.action.value
        result = f"{shown}" + (f" by {d.decided_by}" if d.decided_by else "")
    if d.risk_score:
        result += f" · risk {d.risk_score:.2f}"
    if event.risk_factors:
        top = sorted(event.risk_factors, key=lambda f: f.contribution, reverse=True)[:3]
        controls.append(
            TraceControl(
                control_id="risk",
                control_type="risk_score",
                action=d.action,
                score=d.risk_score,
                reason=", ".join(f"{f.factor.value} {f.value:.2f}" for f in top),
            )
        )
    return TraceStep(
        step="decide",
        result=result,
        changed=d.action != Action.allow or bool(d.applied),
        controls=controls,
    )


def _approval_step(event: AuditEvent) -> TraceStep | None:
    ap = event.approval
    d = event.decision
    if ap is None and not (d and d.action == Action.require_approval):
        return None
    if ap is None:
        return TraceStep(step="approval", result="held for a person's approval", changed=True)
    who = "security team" if ap.approver_scope == "admin" else "team lead"
    until = f" · auto-deny at {hhmm(ap.expires_at)}" if ap.expires_at else ""
    return TraceStep(step="approval", result=f"{ap.status.value}: waiting for the {who}{until}", changed=True)


def _route_step(event: AuditEvent) -> TraceStep:
    r = event.route
    d = event.decision
    if r is None:
        return TraceStep(step="route", result="no model call at this point")
    asked = r.model_requested or event.model_requested
    shown = f"{asked} → {r.model}" if asked and asked != r.model else r.model
    result = f"{shown} ({r.tier.value})" + (" · degraded fallback" if r.degraded else "")
    forced = bool(d and (Action.route_local in d.applied or Action.downgrade in d.applied))
    # the router itself kept sensitive data on a local model (no `route_local` action needed)
    pinned = r.factors.get("sensitivity_rule") == "local_only" or (
        r.tier == ConnectorTier.local and str(r.factors.get("data_class")) in {c.value for c in _SENSITIVE}
    )
    changed = forced or pinned or r.degraded
    action = Action.route_local if changed else Action.allow
    control = TraceControl(control_id="routing", control_type="router", action=action, reason=r.reason)
    return TraceStep(step="route", result=result, changed=changed, controls=[control])


def _identity_step(event: AuditEvent) -> TraceStep:
    p = event.principal
    if p is None:
        return TraceStep(step="identity", result="no principal on this event")
    app = f" · {event.client.app}" if event.client and event.client.app != "unknown" else ""
    via = "without authentication" if p.auth_method == AuthMethod.none else f"via {p.auth_method.value}"
    return TraceStep(step="identity", result=f"{display_name(event)} · {p.kind.value} · {via}{app}")


def trace_steps(event: AuditEvent) -> list[TraceStep]:
    """The decision timeline: identity → normalise → rules → similarity → classifier → judge → decide →
    (approval) → route → output. Empty for events that are not decisions."""
    if event.event_type != EventType.decision or event.decision is None:
        return []
    by_step: dict[str, list[AuditVerdict]] = {}
    for v in event.verdicts:
        by_step.setdefault(_PHASE_STEP.get(v.phase, "rules"), []).append(v)
    steps = [
        _identity_step(event),
        _verdict_step(
            "normalise",
            by_step.get("normalise", []),
            none="not run at this point",
            passed="text checked, nothing to change",
        ),
        _verdict_step(
            "rules",
            by_step.get("rules", []),
            none="no rules ran at this point",
            passed="{n} rules checked, none matched",
        ),
        _verdict_step(
            "similarity",
            by_step.get("similarity", []),
            none="not run at this point",
            passed="no close match to known attacks",
        ),
        _verdict_step(
            "classifier",
            by_step.get("classifier", []),
            none="not run at this point",
            passed="nothing suspicious found",
        ),
        _verdict_step(
            "judge", by_step.get("judge", []), none="not needed: no earlier step was uncertain", passed="judge agreed"
        ),
        _decide_step(event),
    ]
    approval = _approval_step(event)
    if approval is not None:
        steps.append(approval)
    steps.append(_route_step(event))
    steps.append(
        _verdict_step(
            "output",
            by_step.get("output", []),
            none="no output checks at this point",
            passed="output checked, nothing to change",
        )
    )
    return steps


def changed_steps(event: AuditEvent) -> dict[str, str]:
    """Step name → one-line result, only for steps that changed something."""
    return {s.step: s.result for s in trace_steps(event) if s.changed}


# ---------------------------------------------------------------- "what the model saw"


def content_changed(event: AuditEvent) -> bool:
    d = event.decision
    if d is None:
        return False
    return any(a in _CONTENT_ACTIONS for a in (*d.applied, d.action))


def model_saw_note(event: AuditEvent) -> str:
    """One line about what was changed in the content (empty when nothing was)."""
    d = event.decision
    if d is None or not content_changed(event):
        return ""
    actions = {a for a in (*d.applied, d.action)}
    changing = [v for v in event.verdicts if v.action in _CONTENT_ACTIONS]
    n = len(_unique_findings(changing))
    amount = f"{n} value{'s' if n != 1 else ''}" if n else "Some values"
    parts: list[str] = []
    if Action.pseudonymise in actions:
        parts.append(f"{amount} replaced with placeholders; the original values never left Rogatka.")
    if Action.redact in actions:
        parts.append(f"{amount} removed; the original values never left Rogatka.")
    if Action.sanitize in actions:
        parts.append("The suspicious part was removed and the rest passed on unchanged.")
    return " ".join(dict.fromkeys(parts))
