/**
 * Mock data: events, traces and session transcripts (Traffic screen domain).
 * Personas, ids and rule ids come from docs/ux/HANDOFF.md section 6. No raw sensitive values: only
 * placeholders and masked values. Times are relative to "now" via ../time.
 */
import { demoClock } from "../time";
import { seeded } from "./registry";
import type { AuditEvent, EventSummary, EventTrace, SessionTranscript, TraceControl, TraceStep } from "./types";

type Partial_ = Partial<EventSummary> & Pick<EventSummary, "event_id" | "seq" | "timestamp">;

/** Fill the optional EventSummary fields so each fixture only states what matters. */
export function makeEvent(e: Partial_): EventSummary {
  return {
    event_type: "decision",
    severity: "info",
    trace_id: null,
    session_id: null,
    subject: null,
    username: null,
    agent_id: null,
    point: null,
    model: null,
    tool: null,
    action: null,
    risk_score: null,
    latency_ms: null,
    client_app: null,
    data_class: null,
    tier: null,
    session_label: null,
    client_ref: null,
    groups: [],
    rule_ids: [],
    applied: [],
    degraded: false,
    tokens_in: 0,
    tokens_out: 0,
    summary: "",
    changed_steps: {},
    ...e,
  };
}

const ANNA = { subject: "kc-anna-nowak", username: "a.nowak", groups: ["credit-analysts"] };
const JAN = { subject: "kc-jan-kowalski", username: "j.kowalski", groups: ["developers"] };
const PIOTR = { subject: "kc-piotr-zielinski", username: "p.zielinski", groups: ["developers"] };
const BOT = { subject: "agent-research-bot", username: "research-bot", groups: ["agents"] };

function seed(): EventSummary[] {
  return [
    makeEvent({
      event_id: "evt_8f3a2c",
      seq: 1042,
      timestamp: demoClock("14:03:12"),
      trace_id: "tr_8f3a2c",
      session_id: "c_51a8",
      ...ANNA,
      point: "ingress",
      model: "qwen3.8-27b",
      action: "pseudonymise",
      applied: ["pseudonymise", "route_local"],
      rule_ids: ["SEC-PII-01"],
      risk_score: 0.31,
      latency_ms: 212,
      client_app: "librechat",
      data_class: "confidential",
      tier: "local",
      tokens_in: 412,
      tokens_out: 188,
      severity: "low",
      summary:
        "Anna Nowak’s prompt contained a PESEL, an IBAN and a name. They were replaced with placeholders and, because the data is confidential, a local model answered.",
      changed_steps: {
        rules: "found a PESEL and an IBAN, both valid",
        classifier: "found a person’s name",
        decide: "pseudonymise; confidential data stays local",
        route: "auto → qwen3.8-27b (local)",
      },
      session_label: { data_class: "confidential", trust: "trusted", since: demoClock("14:03:12"), local_only: true },
      client_ref: { kind: "conversation", id: "c_51a8", client: "LibreChat", message_count: 6, started_at: demoClock("13:58:00") },
    }),
    makeEvent({
      event_id: "evt_9b21e4",
      seq: 1041,
      timestamp: demoClock("14:02:41"),
      trace_id: "tr_9b21e4",
      session_id: "s_9e21",
      ...JAN,
      point: "tool_call",
      tool: "bash",
      action: "require_approval",
      applied: ["require_approval"],
      rule_ids: ["SEC-FLOW-01"],
      risk_score: 0.78,
      latency_ms: 9,
      client_app: "opencode",
      data_class: "confidential",
      severity: "high",
      summary:
        "Jan’s agent tried to push to a private remote after reading untrusted repo content and a secret. It is waiting for a security approval.",
      changed_steps: {
        rules: "Rule of Two: untrusted + secret + external target",
        decide: "risk 0.78 → hold for a person",
        approval: "waiting for security · auto-deny in 9:40",
      },
      session_label: { data_class: "confidential", trust: "untrusted", since: demoClock("14:02:30"), local_only: true },
      client_ref: { kind: "session", id: "s_9e21", client: "OpenCode on dev-jk-01 · repo loan-calc", message_count: 14, started_at: demoClock("13:50:00") },
    }),
    makeEvent({
      event_id: "evt_9a0c33",
      seq: 1039,
      timestamp: demoClock("14:01:20"),
      trace_id: "tr_9a0c33",
      session_id: "s_9e21",
      ...JAN,
      point: "tool_call",
      tool: "bash",
      action: "block",
      applied: ["block"],
      rule_ids: ["FEED-PKG-0007"],
      latency_ms: 5,
      client_app: "opencode",
      data_class: "internal",
      severity: "medium",
      summary:
        "Jan’s agent tried to install litellm 1.82.8, a known backdoored release. The signature feed blocked it.",
      changed_steps: { rules: "matches feed signature for litellm 1.82.8", decide: "block" },
      client_ref: { kind: "session", id: "s_9e21", client: "OpenCode on dev-jk-01 · repo loan-calc", message_count: 14, started_at: demoClock("13:50:00") },
    }),
    makeEvent({
      event_id: "evt_8f2c90",
      seq: 1037,
      timestamp: demoClock("14:02:12"),
      trace_id: "tr_8f2c90",
      session_id: "s_77c1",
      ...BOT,
      agent_id: "research-bot",
      point: "tool_call",
      tool: "web.search",
      action: "block",
      applied: ["block"],
      rule_ids: ["BUDGET-LOOP-01"],
      latency_ms: 3,
      client_app: "agent",
      data_class: "public",
      severity: "medium",
      summary:
        "research-bot repeated the same search three times in 60 seconds. The loop detector blocked it and opened the session’s circuit breaker.",
      changed_steps: { rules: "same search 3× in 60 s · 120 / 120 GPU-s", decide: "block and open the breaker" },
      client_ref: { kind: "session", id: "s_77c1", client: "research-bot run for Anna · 23 steps", message_count: 23, started_at: demoClock("13:40:00") },
    }),
    makeEvent({
      event_id: "evt_8d5e10",
      seq: 1030,
      timestamp: demoClock("14:00:47"),
      trace_id: "tr_8d5e10",
      session_id: "s_7d02",
      ...PIOTR,
      point: "ingress",
      model: "smart → gemini-flash",
      action: "allow",
      applied: ["allow"],
      risk_score: 0.04,
      latency_ms: 41,
      client_app: "opencode",
      data_class: "internal",
      tier: "cloud",
      tokens_in: 96,
      tokens_out: 310,
      summary: "Piotr’s general question went to Gemini through the smart alias. Nothing sensitive was found.",
      changed_steps: { route: "smart → gemini-flash (cloud, internal data allowed)" },
      client_ref: { kind: "session", id: "s_7d02", client: "OpenCode on dev-pz-01", message_count: 4, started_at: demoClock("13:55:00") },
    }),
  ];
}

export const events = seeded(seed);

const STEP_ORDER: TraceStep["step"][] = [
  "identity",
  "normalise",
  "rules",
  "similarity",
  "classifier",
  "judge",
  "decide",
  "approval",
  "route",
  "output",
];

const DEFAULT_RESULT: Record<TraceStep["step"], string> = {
  identity: "user identified",
  normalise: "nothing hidden",
  rules: "no rule matched",
  similarity: "not like known attacks",
  classifier: "nothing found",
  judge: "not needed",
  decide: "allow",
  approval: "",
  route: "no change",
  output: "checked",
};

/** Detailed controls exist for Anna's PESEL trace only (as in the prototype); other traces list their step results. */
function annaSteps(): TraceStep[] {
  const ctl = (
    control_id: string,
    control_type: string,
    action: TraceControl["action"],
    extra: Partial<TraceControl> = {},
  ): TraceControl => ({
    control_id,
    control_type,
    action,
    rule_ids: [control_id],
    score: null,
    threshold: null,
    latency_ms: 1,
    status: "ok",
    findings: [],
    reason: null,
    ...extra,
  });
  return [
    { step: "identity", result: "user identified", ms: 0.6, changed: false, controls: [] },
    { step: "normalise", result: "nothing hidden", ms: 0.4, changed: false, controls: [] },
    {
      step: "rules",
      result: "found a PESEL and an IBAN, both valid",
      ms: 7,
      changed: true,
      controls: [
        ctl("SEC-PII-01", "pii.checksum", "pseudonymise", { reason: "PESEL found, checksum valid", findings: ["PESEL ***-**-**123"] }),
        ctl("SEC-PII-01", "pii.checksum", "pseudonymise", { reason: "IBAN found, mod-97 valid", findings: ["PL** **** … 2874"] }),
        ctl("SEC-SECRET-01", "secret.scan", "allow", { reason: "no secrets or keys" }),
      ],
    },
    { step: "similarity", result: "not like known attacks", ms: 14, changed: false, controls: [] },
    {
      step: "classifier",
      result: "found a person’s name",
      ms: 48,
      changed: true,
      controls: [
        ctl("SEC-PII-01", "pii.ner", "pseudonymise", { reason: "person name", score: 0.97, threshold: 0.5, findings: ["<PERSON_1>"] }),
        ctl("SEC-PI-01", "injection.classifier", "allow", { reason: "prompt injection", score: 0.03, threshold: 0.5 }),
      ],
    },
    { step: "judge", result: "not needed", ms: null, changed: false, controls: [] },
    {
      step: "decide",
      result: "pseudonymise; confidential data stays local",
      ms: 0.3,
      changed: true,
      controls: [
        ctl("risk", "risk.score", "pseudonymise", { reason: "data sensitivity 0.24 · others 0.07", score: 0.31, threshold: 0.6 }),
        ctl("LOCK-01", "org.lock", "route_local", { reason: "cloud models get internal data at most" }),
      ],
    },
    { step: "route", result: "auto → qwen3.8-27b (local)", ms: 0.2, changed: true, controls: [] },
    { step: "output", result: "checked", ms: 141, changed: false, controls: [] },
  ];
}

export function buildSteps(e: EventSummary): TraceStep[] {
  if (e.event_id === "evt_8f3a2c") return annaSteps();
  const names = STEP_ORDER.filter((s) => s !== "approval" || e.changed_steps.approval);
  return names.map((step) => {
    const changed = Object.prototype.hasOwnProperty.call(e.changed_steps, step);
    return { step, result: changed ? e.changed_steps[step] : DEFAULT_RESULT[step], ms: null, changed, controls: [] };
  });
}

const FAKE_HASH = (n: number) => n.toString(16).padStart(64, "0");

export function toAuditEvent(e: EventSummary): AuditEvent {
  return {
    schema_version: "1.0",
    event_id: e.event_id,
    seq: e.seq,
    timestamp: e.timestamp,
    event_type: e.event_type as AuditEvent["event_type"],
    severity: e.severity,
    trace_id: e.trace_id,
    session_id: e.session_id,
    principal: e.subject
      ? { subject: e.subject, kind: e.agent_id ? "agent" : "user", username: e.username, groups: e.groups, agent_id: e.agent_id, auth_method: "jwt" }
      : null,
    client: e.client_app ? { app: e.client_app } : null,
    point: e.point,
    tool: e.tool,
    model: e.model,
    decision: e.action
      ? { action: e.action, applied: e.applied, final: true, rule_ids: e.rule_ids, risk_score: e.risk_score ?? 0, reason: e.summary }
      : null,
    verdicts: [],
    risk_factors: [],
    versions: { policy: "v8", grants: "12", signatures: "f-2026.10.03.4", gateway: "0.1.0" },
    taxonomy: { owasp_llm: [], owasp_agentic: [], owasp_mcp: [], atlas: [], cve: [] },
    detail: {},
    prev_hash: FAKE_HASH(e.seq - 1),
    hash: FAKE_HASH(e.seq),
  };
}

const MODEL_SAW: Record<string, { text: string; note: string }> = {
  evt_8f3a2c: {
    text: "Przygotuj notatkę dla klienta <PERSON_1>, PESEL <PESEL_1>, IBAN <IBAN_1>",
    note: "PESEL ***-**-**123 · IBAN PL** … 2874 · put back in the answer for Anna only",
  },
};

export function buildTrace(e: EventSummary): EventTrace {
  const saw = MODEL_SAW[e.event_id];
  return {
    event: e,
    steps: buildSteps(e),
    model_saw: saw?.text ?? null,
    model_saw_note: saw?.note ?? "",
    record: toAuditEvent(e),
  };
}

export function buildTranscript(sessionId: string): SessionTranscript | null {
  const list = events.items.filter((e) => e.session_id === sessionId).sort((a, b) => a.seq - b.seq);
  if (list.length === 0) return null;
  const first = list[0];
  const role = (p: EventSummary["point"]): SessionTranscript["turns"][number]["role"] =>
    p === "ingress" ? "user" : p === "egress" ? "assistant" : p === "tool_result" ? "tool_result" : "tool_call";
  return {
    session_id: sessionId,
    client_ref: first.client_ref,
    subject: first.subject,
    username: first.username,
    groups: first.groups,
    session_label: first.session_label,
    started_at: first.client_ref?.started_at ?? first.timestamp,
    last_at: list[list.length - 1].timestamp,
    truncated: false,
    turns: list.map((e) => ({
      event_id: e.event_id,
      trace_id: e.trace_id,
      seq: e.seq,
      timestamp: e.timestamp,
      point: e.point,
      role: role(e.point),
      text: MODEL_SAW[e.event_id]?.text ?? null,
      retained: !!MODEL_SAW[e.event_id],
      model: e.model,
      tool: e.tool,
      action: e.action,
      applied: e.applied,
      rule_ids: e.rule_ids,
      summary: e.summary,
    })),
  };
}
