/**
 * Mock data: events, traces and session transcripts (Traffic screen domain).
 * The 12 demo events come from `EVENTS` in docs/ux/design-reference/LiveTraffic.dc.html, adapted to the HANDOFF
 * section 6 personas and the section 7.1 model lineup (gemini/flash, gemini/pro, local/qwen3.8-27b, local/loan-memo).
 * Older, mostly allowed traffic is generated below so paging and "Hide allowed" have something to work on.
 * No raw sensitive values: only placeholders and masked values. Times are relative to "now" via ../time.
 */
import { demoClock, daysAgo, minutesAgo } from "../time";
import { seeded } from "./registry";
import type { AuditEvent, EventSummary, EventTrace, SessionTranscript, TraceControl, TraceStep } from "./types";

type Partial_ = Partial<EventSummary> & Pick<EventSummary, "event_id" | "seq" | "timestamp">;
type Step = TraceStep["step"];

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

// ---------------------------------------------------------------------------------------------------------------
// People (subjects follow mocks/db/users.ts: `kc-<ascii name>`; agents `agent-<name>`)

const ANNA = { subject: "kc-anna-nowak", username: "a.nowak", groups: ["credit-analysts"] };
const JAN = { subject: "kc-jan-kowalski", username: "j.kowalski", groups: ["developers"] };
const PIOTR = { subject: "kc-piotr-zielinski", username: "p.zielinski", groups: ["developers"] };
const MARTA = { subject: "kc-marta-lis", username: "m.lis", groups: ["credit-analysts"] };
const TOMASZ = { subject: "kc-tomasz-wisniewski", username: "t.wisniewski", groups: ["credit-analysts"] };
const EWA = { subject: "kc-ewa-grabowska", username: "e.grabowska", groups: ["operations"] };
const BOT = { subject: "agent-research-bot", username: "research-bot", groups: ["agents"], agent_id: "research-bot" };

// Client conversations / sessions of the demo stories.
const C_51A8 = () => ({ kind: "conversation" as const, id: "c_51a8", client: "LibreChat", message_count: 6, started_at: demoClock("13:58:00") });
const C_4F02 = () => ({ kind: "conversation" as const, id: "c_4f02", client: "LibreChat", message_count: 2, started_at: demoClock("13:59:40") });
const C_3E90 = () => ({ kind: "conversation" as const, id: "c_3e90", client: "LibreChat", message_count: 9, started_at: demoClock("13:41:00") });
const S_9E21 = () => ({ kind: "session" as const, id: "s_9e21", client: "OpenCode on dev-jk-01 · repo loan-calc", message_count: 14, started_at: demoClock("13:50:00") });
const S_77C1 = () => ({ kind: "session" as const, id: "s_77c1", client: "research-bot run for Anna", message_count: 23, started_at: demoClock("13:40:00") });
const S_4C10 = () => ({ kind: "session" as const, id: "s_4c10", client: "OpenCode on dev-an-02", message_count: 3, started_at: demoClock("14:01:30") });
const S_7D02 = () => ({ kind: "session" as const, id: "s_7d02", client: "OpenCode on dev-pz-01", message_count: 4, started_at: demoClock("13:55:00") });

// ---------------------------------------------------------------------------------------------------------------
// Trace extras per event: control details, step timings, what the model saw, transcript text, audit `detail`.

interface TraceExtra {
  ms?: Partial<Record<Step, number | null>>;
  controls?: Partial<Record<Step, TraceControl[]>>;
  /** What the model saw, when Rogatka changed the content (placeholders / removed key / removed sentence). */
  saw?: { text: string; note: string };
  /** Redacted transcript text of this turn (as stored by Rogatka). Defaults to `saw.text`. */
  text?: string;
  /** Free-form audit `detail` (e.g. the command of a tool call). */
  detail?: Record<string, unknown>;
}

function ctl(
  control_id: string,
  control_type: string,
  action: TraceControl["action"],
  extra: Partial<TraceControl> = {},
): TraceControl {
  return {
    control_id,
    control_type,
    action,
    rule_ids: /^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$/.test(control_id) ? [control_id] : [],
    score: null,
    threshold: null,
    latency_ms: 1,
    status: "ok",
    findings: [],
    reason: null,
    ...extra,
  };
}

const EXTRAS: Record<string, TraceExtra> = {
  // Anna's PESEL + IBAN prompt (the hero trace: every step has a time, four steps have controls).
  evt_8f3a2c: {
    ms: { identity: 0.6, normalise: 0.4, rules: 7, similarity: 14, classifier: 48, judge: null, decide: 0.3, route: 0.2, output: 141 },
    controls: {
      rules: [
        ctl("SEC-PII-01", "pii.checksum", "pseudonymise", { reason: "PESEL found, checksum valid", findings: ["PESEL ***-**-**123"] }),
        ctl("SEC-PII-01", "pii.checksum", "pseudonymise", { reason: "IBAN found, mod-97 valid", findings: ["PL** **** … 2874"] }),
        ctl("SEC-SECRET-01", "secret.scan", "allow", { reason: "no secrets or keys" }),
      ],
      classifier: [
        ctl("SEC-PII-01", "pii.ner", "pseudonymise", { reason: "person name", score: 0.97, threshold: 0.5, findings: ["<PERSON_1>"] }),
        ctl("SEC-PI-01", "injection.classifier", "allow", { reason: "prompt injection", score: 0.03, threshold: 0.5 }),
      ],
      decide: [
        ctl("risk", "risk.score", "pseudonymise", { reason: "data sensitivity 0.24 · others 0.07", score: 0.31, threshold: 0.6 }),
        ctl("LOCK-01", "org.lock", "route_local", { reason: "cloud models get internal data at most" }),
        ctl("SEC-SESSION-01", "session.label", "route_local", { reason: "session is confidential from now on: local models only" }),
      ],
      route: [ctl("routing", "router", "route_local", { reason: "no specialist matched; confidential → local", score: 0.41, threshold: 0.8 })],
    },
    saw: {
      text: "Prepare a note for client <PERSON_1>, PESEL <PESEL_1>, IBAN <IBAN_1>. Monthly repayment from this account.",
      note: "PESEL ***-**-**123 · IBAN PL** … 2874 · put back in the answer for Anna only",
    },
  },
  evt_8f3a31: {
    ms: { output: 14 },
    controls: {
      output: [
        ctl("SEC-PII-01", "pii.restore", "allow", { reason: "3 placeholders restored for Anna only", findings: ["<PERSON_1>", "<PESEL_1>", "<IBAN_1>"] }),
        ctl("SEC-SAFE-01", "judge.content_safety", "allow", { reason: "content safety", score: 0.02, threshold: 0.6 }),
      ],
    },
    text: "Client note for <PERSON_1>: identity confirmed (PESEL <PESEL_1>). The monthly repayment of 4 120 PLN will be collected from <IBAN_1> on the 10th of each month.",
  },
  evt_8f39e1: {
    ms: { classifier: 21, judge: 290 },
    controls: {
      classifier: [ctl("SEC-PI-01", "injection.classifier", "sanitize", { reason: "instructions aimed at the agent", score: 0.71, threshold: 0.5 })],
      judge: [
        ctl("SEC-PI-01", "judge.injected_span", "sanitize", {
          reason: "one sentence asks the agent to e-mail the report outside the company",
          findings: ["1 injected sentence"],
        }),
      ],
      decide: [ctl("risk", "risk.score", "sanitize", { reason: "untrusted web content · injection confirmed", score: 0.52, threshold: 0.6 })],
    },
    saw: {
      text: "…rates for SME loans in 2026 are expected to … [removed: instruction to e-mail the report] … source: nbp.pl",
      note: "only the injected sentence was removed",
    },
  },
  evt_9b21e4: {
    ms: { rules: 3, decide: 0.4 },
    controls: {
      rules: [
        ctl("SEC-FLOW-01", "flow.rule_of_two", "require_approval", {
          reason: "Rule of Two: untrusted + secret + external target",
          findings: ["untrusted README read", "secret in config/settings.py", "remote outside company git"],
        }),
      ],
      decide: [ctl("risk", "risk.score", "require_approval", { reason: "data flow 0.62 · tool 0.16", score: 0.78, threshold: 0.6 })],
    },
    detail: { command: "git push origin feature/loan-calc", approval_id: "apr-0193" },
    text: "git push origin feature/loan-calc",
  },
  evt_9b1f07: {
    ms: { rules: 2 },
    controls: {
      rules: [ctl("SEC-SECRET-01", "secret.scan", "redact", { reason: "API key found", findings: ["‹SECRET:api_key› · line 14"] })],
    },
    saw: { text: "SCORING_URL = \"https://scoring.corp.example\"\nSCORING_API_KEY = ‹SECRET:api_key›", note: "the key never reached the model" },
    detail: { command: "config/settings.py" },
  },
  evt_8f2c90: {
    controls: {
      rules: [
        ctl("BUDGET-LOOP-01", "loop.detector", "block", { reason: "same search repeated", score: 3, threshold: 3, findings: ["3× in 60 s"] }),
        ctl("BUDGET-LOOP-01", "budget.gpu", "block", { reason: "session GPU budget used up", findings: ["120 / 120 GPU-s"] }),
      ],
    },
    detail: { command: "web.search “SME loan rates 2026 Poland”", breaker: "s_77c1" },
    text: "web.search “SME loan rates 2026 Poland”",
  },
  evt_8e77a2: {
    controls: { rules: [ctl("AUTHZ-TOOL-01", "authz.tool", "block", { reason: "bash denied for Anna", findings: ["grant g-0415"] })] },
    detail: { command: "ls -la" },
    text: "ls -la",
  },
  evt_9a0c33: {
    controls: {
      rules: [ctl("FEED-PKG-0007", "feed.signature", "block", { reason: "known backdoored release", findings: ["litellm==1.82.8"] })],
    },
    detail: { command: "pip install litellm==1.82.8" },
    text: "pip install litellm==1.82.8",
  },
  evt_8d5e10: {
    ms: { route: 0.2 },
    controls: { route: [ctl("routing", "router", "allow", { reason: "smart → gemini/flash; internal data allowed in the cloud" })] },
    text: "How do I mock a datetime in pytest so the scoring tests stop depending on the clock?",
  },
  evt_8c9911: {
    controls: {
      rules: [
        ctl("SEC-MCP-01", "mcp.pinning", "block", {
          reason: "tool description changed since approval",
          findings: ["hidden instruction", "reads ~/.ssh", "new parameter: context"],
        }),
        ctl("FEED-MCP-0009", "feed.signature", "block", { reason: "matches a known MCP rug-pull pattern" }),
      ],
    },
    detail: { server: "docs-search", incident_id: "inc-0057" },
  },
  evt_8c7a04: {
    ms: { rules: 6, classifier: 44, route: 0.3 },
    controls: {
      rules: [ctl("SEC-PII-01", "pii.checksum", "pseudonymise", { reason: "PESEL found, checksum valid", findings: ["PESEL ***-**-**481"] })],
      classifier: [ctl("routing", "task.classifier", "allow", { reason: "task: loan memo", score: 0.91, threshold: 0.8 })],
      route: [ctl("routing", "router", "route_local", { reason: "specialist local/loan-memo matched", score: 0.91, threshold: 0.8 })],
    },
    saw: {
      text: "Write a credit memo for the following application: applicant <PERSON_1>, PESEL <PESEL_1>, amount 240 000 PLN, purpose: working capital.",
      note: "PESEL ***-**-**481 · put back in the answer for Anna only",
    },
  },
  evt_8b6f55: {
    ms: { judge: 380 },
    controls: {
      judge: [ctl("SEC-SAFE-01", "judge.content_safety", "monitor", { reason: "could mislead a customer about guaranteed approval", score: 0.64, threshold: 0.6 })],
      decide: [ctl("SEC-SAFE-01", "mode", "monitor", { reason: "rule is in monitor mode: log only" })],
    },
    text: "Based on these numbers the customer will certainly be approved, so you can tell them the loan is guaranteed.",
  },
  // Earlier turns of Anna's conversation c_51a8 (before it became confidential).
  evt_8a10c4: { text: "What should a short client note for a working-capital loan contain?" },
  evt_8a10d9: { text: "A short client note usually covers: purpose of the loan, amount and term, repayment schedule, collateral and a one-line risk view." },
  evt_8e5512: { text: "Make it more formal and add a repayment section." },
  evt_8e5530: { text: "Here is a more formal version with a repayment section. Fill in the client details and I will finish it." },
};

// ---------------------------------------------------------------------------------------------------------------
// The demo events (prototype order, newest first). `seq` is assigned from the timestamps below.

type Spec = Omit<Partial_, "seq">;

function demoEvents(): Spec[] {
  return [
    {
      event_id: "evt_8f3a31",
      timestamp: demoClock("14:03:31"),
      trace_id: "tr_8f3a31",
      session_id: "c_51a8",
      ...ANNA,
      point: "egress",
      model: "local/qwen3.8-27b",
      action: "allow",
      applied: ["allow"],
      risk_score: 0.05,
      latency_ms: 14,
      client_app: "librechat",
      data_class: "confidential",
      tier: "local",
      tokens_in: 0,
      tokens_out: 188,
      summary: "The local model’s answer to Anna passed the output checks, and the placeholders were restored for her.",
      changed_steps: { output: "checked; 3 placeholders restored for Anna" },
      session_label: { data_class: "confidential", trust: "trusted", since: demoClock("14:03:12"), local_only: true },
      client_ref: C_51A8(),
    },
    {
      event_id: "evt_8f3a2c",
      timestamp: demoClock("14:03:12"),
      trace_id: "tr_8f3a2c",
      session_id: "c_51a8",
      ...ANNA,
      point: "ingress",
      model: "local/qwen3.8-27b",
      action: "pseudonymise",
      applied: ["pseudonymise", "route_local"],
      rule_ids: ["SEC-PII-01"],
      risk_score: 0.31,
      latency_ms: 212,
      client_app: "librechat",
      data_class: "confidential",
      tier: "local",
      tokens_in: 412,
      tokens_out: 0,
      severity: "low",
      summary:
        "Anna Nowak’s prompt contained a PESEL, an IBAN and a name. They were replaced with placeholders and, because the data is confidential, a local model answered.",
      changed_steps: {
        rules: "found a PESEL and an IBAN, both valid",
        classifier: "found a person’s name",
        decide: "pseudonymise; confidential data stays local",
        route: "auto → local/qwen3.8-27b (local)",
      },
      session_label: { data_class: "confidential", trust: "trusted", since: demoClock("14:03:12"), local_only: true },
      client_ref: C_51A8(),
    },
    {
      event_id: "evt_8f39e1",
      timestamp: demoClock("14:02:58"),
      trace_id: "tr_8f39e1",
      session_id: "s_77c1",
      ...BOT,
      point: "tool_result",
      tool: "web.search",
      action: "sanitize",
      applied: ["sanitize"],
      rule_ids: ["SEC-PI-01"],
      risk_score: 0.52,
      latency_ms: 38,
      client_app: "agent",
      data_class: "public",
      severity: "medium",
      summary:
        "A web page returned to research-bot contained instructions aimed at the agent. The injected part was removed and the rest passed on.",
      changed_steps: {
        classifier: "possible injection in the page (0.71)",
        judge: "confirmed the injected sentence",
        decide: "sanitize: remove it, keep the rest",
      },
      client_ref: S_77C1(),
    },
    {
      event_id: "evt_9b21e4",
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
      session_label: { data_class: "restricted", trust: "untrusted", since: demoClock("14:02:30"), local_only: true },
      client_ref: S_9E21(),
    },
    {
      event_id: "evt_9b1f07",
      timestamp: demoClock("14:02:30"),
      trace_id: "tr_9b1f07",
      session_id: "s_9e21",
      ...JAN,
      point: "tool_result",
      tool: "read",
      action: "redact",
      applied: ["redact"],
      rule_ids: ["SEC-SECRET-01"],
      risk_score: 0.4,
      latency_ms: 6,
      client_app: "opencode",
      data_class: "restricted",
      severity: "medium",
      summary: "A file Jan’s agent read contained an API key. The key was removed before the model saw the file.",
      changed_steps: { rules: "API key found", decide: "redact the key" },
      session_label: { data_class: "restricted", trust: "untrusted", since: demoClock("14:02:30"), local_only: true },
      client_ref: S_9E21(),
    },
    {
      event_id: "evt_8f2c90",
      timestamp: demoClock("14:02:12"),
      trace_id: "tr_8f2c90",
      session_id: "s_77c1",
      ...BOT,
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
      client_ref: S_77C1(),
    },
    {
      event_id: "evt_8e77a2",
      timestamp: demoClock("14:01:55"),
      trace_id: "tr_8e77a2",
      session_id: "s_4c10",
      ...ANNA,
      point: "tool_call",
      tool: "bash",
      action: "block",
      applied: ["block"],
      rule_ids: ["AUTHZ-TOOL-01"],
      latency_ms: 4,
      client_app: "opencode",
      data_class: "internal",
      severity: "low",
      summary: "Anna tried to run a shell command, but bash has been revoked for her. The call was blocked before it ran.",
      changed_steps: { rules: "bash denied for Anna (grant g-0415)", decide: "block" },
      client_ref: S_4C10(),
    },
    {
      event_id: "evt_9a0c33",
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
      summary: "Jan’s agent tried to install litellm 1.82.8, a known backdoored release. The signature feed blocked it.",
      changed_steps: { rules: "matches feed signature for litellm 1.82.8", decide: "block" },
      client_ref: S_9E21(),
    },
    {
      event_id: "evt_8d5e10",
      timestamp: demoClock("14:00:47"),
      trace_id: "tr_8d5e10",
      session_id: "s_7d02",
      ...PIOTR,
      point: "ingress",
      model: "gemini/flash",
      action: "allow",
      applied: ["allow"],
      risk_score: 0.04,
      latency_ms: 41,
      client_app: "opencode",
      data_class: "internal",
      tier: "cloud",
      tokens_in: 96,
      tokens_out: 310,
      summary: "Piotr’s general question went to Gemini Flash through the smart alias. Nothing sensitive was found.",
      changed_steps: { route: "smart → gemini/flash (cloud, internal data allowed)" },
      client_ref: S_7D02(),
    },
    {
      event_id: "evt_8c9911",
      timestamp: demoClock("14:00:02"),
      trace_id: "tr_8c9911",
      session_id: "s_77c1",
      ...BOT,
      point: "mcp_tools_list",
      tool: "docs-search.search_docs",
      action: "block",
      applied: ["block"],
      rule_ids: ["SEC-MCP-01"],
      latency_ms: 2,
      client_app: "mcp",
      severity: "high",
      summary:
        "The docs-search MCP server changed a tool description after it was approved. The tool was quarantined and an incident opened.",
      changed_steps: { rules: "tool description changed since approval", decide: "quarantine the tool, open inc-0057" },
      client_ref: S_77C1(),
    },
    {
      event_id: "evt_8c7a04",
      timestamp: demoClock("13:59:48"),
      trace_id: "tr_8c7a04",
      session_id: "c_4f02",
      ...ANNA,
      point: "ingress",
      model: "local/loan-memo",
      action: "pseudonymise",
      applied: ["pseudonymise", "route_local"],
      rule_ids: ["SEC-PII-01"],
      risk_score: 0.22,
      latency_ms: 188,
      client_app: "librechat",
      data_class: "confidential",
      tier: "local",
      tokens_in: 1_240,
      severity: "low",
      summary:
        "Anna used the loan-memo skill. auto picked the local specialist local/loan-memo and personal data was pseudonymised.",
      changed_steps: {
        rules: "found a PESEL",
        classifier: "task: loan memo (0.91)",
        decide: "pseudonymise",
        route: "auto → local/loan-memo (local specialist)",
      },
      session_label: { data_class: "confidential", trust: "trusted", since: demoClock("13:59:48"), local_only: true },
      client_ref: C_4F02(),
    },
    {
      event_id: "evt_8b6f55",
      timestamp: demoClock("13:59:10"),
      trace_id: "tr_8b6f55",
      session_id: "c_3e90",
      ...MARTA,
      point: "egress",
      model: "gemini/flash",
      action: "monitor",
      applied: ["monitor"],
      rule_ids: ["SEC-SAFE-01"],
      risk_score: 0.35,
      latency_ms: 402,
      client_app: "librechat",
      data_class: "internal",
      tier: "cloud",
      tokens_out: 286,
      severity: "low",
      summary: "The content-safety judge flagged an answer to Marta. In monitor mode it was logged, not blocked.",
      changed_steps: { judge: "content-safety flag (0.64)", decide: "monitor mode: log only" },
      client_ref: C_3E90(),
    },
    // Earlier turns of c_51a8 (Gemini Flash answered; the conversation became confidential at 14:03).
    ...anna51a8Earlier(),
  ];
}

function anna51a8Earlier(): Spec[] {
  const base = {
    ...ANNA,
    session_id: "c_51a8",
    client_app: "librechat",
    data_class: "internal" as const,
    tier: "cloud" as const,
    model: "gemini/flash",
    action: "allow" as const,
    applied: ["allow" as const],
    client_ref: C_51A8(),
  };
  return [
    { ...base, event_id: "evt_8a10c4", trace_id: "tr_8a10c4", timestamp: demoClock("13:58:10"), point: "ingress", risk_score: 0.03, latency_ms: 36, tokens_in: 64,
      summary: "Anna’s prompt went to Gemini Flash. Nothing sensitive was found.", changed_steps: { route: "auto → gemini/flash (cloud)" } },
    { ...base, event_id: "evt_8a10d9", trace_id: "tr_8a10d9", timestamp: demoClock("13:58:24"), point: "egress", risk_score: 0.02, latency_ms: 11, tokens_out: 240,
      summary: "The answer to Anna passed the output checks." },
    { ...base, event_id: "evt_8e5512", trace_id: "tr_8e5512", timestamp: demoClock("14:01:40"), point: "ingress", risk_score: 0.03, latency_ms: 33, tokens_in: 310,
      summary: "Anna’s prompt went to Gemini Flash. Nothing sensitive was found.", changed_steps: { route: "auto → gemini/flash (cloud)" } },
    { ...base, event_id: "evt_8e5530", trace_id: "tr_8e5530", timestamp: demoClock("14:01:52"), point: "egress", risk_score: 0.02, latency_ms: 12, tokens_out: 402,
      summary: "The answer to Anna passed the output checks." },
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// Background traffic: earlier today and the past days, mostly allowed.

interface Persona {
  who: typeof ANNA & { agent_id?: string };
  first: string;
  app: "librechat" | "opencode" | "agent";
  device?: string;
}

const PERSONAS: Persona[] = [
  { who: PIOTR, first: "Piotr", app: "opencode", device: "dev-pz-01" },
  { who: MARTA, first: "Marta", app: "librechat" },
  { who: JAN, first: "Jan", app: "opencode", device: "dev-jk-01" },
  { who: TOMASZ, first: "Tomasz", app: "librechat" },
  { who: EWA, first: "Ewa", app: "librechat" },
  { who: ANNA, first: "Anna", app: "librechat" },
  { who: BOT, first: "research-bot", app: "agent" },
];

const PROMPTS = [
  "Summarise the attached meeting notes in five bullet points.",
  "Rewrite this paragraph in plain English for a customer letter.",
  "What is the difference between a fixed and a variable rate loan?",
  "Draft a short reply thanking the client for the documents.",
  "Explain this stack trace and suggest a fix.",
  "Turn these notes into a checklist for the onboarding call.",
];
const COMMANDS = ["git status", "pytest -q tests/scoring", "ls src/", "git diff --stat", "npm run lint"];
const SEARCHES = ["web.search “ECB rate decision October 2026”", "web.search “SME lending survey 2026”", "web.search “NBP reference rate history”"];

function hex4(s: string): string {
  let h = 0x811c9dc5;
  for (const ch of s) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return (h & 0xffff).toString(16).padStart(4, "0");
}

function backgroundEvents(): Spec[] {
  const out: Spec[] = [];
  const at = (i: number) => (i < 46 ? minutesAgo(12 + i * 29) : daysAgo(2 + (i - 46) * 0.7));
  for (let i = 0; i < 54; i++) {
    const p = PERSONAS[i % PERSONAS.length];
    const timestamp = at(i);
    const bucket = i < 46 ? Math.floor((12 + i * 29) / 180) : 100 + i;
    const session_id = `${p.app === "librechat" ? "c" : "s"}_${hex4(`${p.who.username}-${bucket}`)}`;
    const id = hex4(`evt-${i}`) + hex4(`evt2-${i}`).slice(0, 2);
    const common = {
      ...p.who,
      event_id: `evt_${id}`,
      trace_id: `tr_${id}`,
      timestamp,
      session_id,
      client_app: p.app,
      action: "allow" as const,
      applied: ["allow" as const],
      data_class: "internal" as const,
    };
    const v = i % 3;
    if (p.app === "agent") {
      out.push({ ...common, point: "tool_call", tool: "web.search", data_class: "public", latency_ms: 3, risk_score: 0.06,
        summary: "research-bot ran a web search for Anna. Nothing unusual was found.", _text: SEARCHES[i % SEARCHES.length] } as Spec);
    } else if (p.app === "opencode" && v === 1) {
      out.push({ ...common, point: "tool_call", tool: "bash", latency_ms: 4, risk_score: 0.05,
        summary: `${p.first}’s agent ran a shell command. Nothing matched a rule, so it ran.`, _text: COMMANDS[i % COMMANDS.length] } as Spec);
    } else if (v === 2) {
      out.push({ ...common, point: "egress", model: "gemini/flash", tier: "cloud", latency_ms: 10 + (i % 7), risk_score: 0.02, tokens_out: 180 + i * 7,
        summary: `The answer to ${p.first} passed the output checks.` });
    } else {
      const pro = i % 5 === 0;
      out.push({ ...common, point: "ingress", model: pro ? "gemini/pro" : "gemini/flash", tier: "cloud", latency_ms: 30 + (i % 11), risk_score: 0.03,
        tokens_in: 60 + i * 13,
        summary: pro
          ? `${p.first}’s longer question went to Gemini Pro because it looked complex. Nothing sensitive was found.`
          : `${p.first}’s prompt went to Gemini Flash. Nothing sensitive was found.`,
        changed_steps: { route: pro ? "auto → gemini/pro (complex request)" : "auto → gemini/flash (cloud)" },
        _text: PROMPTS[i % PROMPTS.length] } as Spec);
    }
  }
  // One monitored and one blocked request yesterday, so older pages are not all "allow".
  out[20] = { ...out[20], action: "monitor", applied: ["monitor"], rule_ids: ["SEC-PI-01"], risk_score: 0.38, severity: "low",
    summary: "A prompt looked a little like a known jailbreak. In monitor mode it was logged, not blocked.",
    changed_steps: { similarity: "0.58 similar to a known jailbreak", decide: "monitor mode: log only" } };
  return out;
}

/** Derive `client_ref` for background sessions: first turn and count from the events themselves. */
function withClientRefs(list: EventSummary[]): EventSummary[] {
  const bySession = new Map<string, EventSummary[]>();
  for (const e of list) if (e.session_id && !e.client_ref) bySession.set(e.session_id, [...(bySession.get(e.session_id) ?? []), e]);
  for (const [sid, evs] of bySession) {
    const first = evs.reduce((a, b) => (a.timestamp < b.timestamp ? a : b));
    const persona = PERSONAS.find((p) => p.who.username === first.username);
    const client =
      first.client_app === "librechat" ? "LibreChat" : first.client_app === "agent" ? "research-bot run for Anna" : `OpenCode on ${persona?.device ?? "dev"}`;
    const ref = { kind: sid.startsWith("c_") ? ("conversation" as const) : ("session" as const), id: sid, client, message_count: evs.length, started_at: first.timestamp };
    for (const e of evs) e.client_ref = ref;
  }
  return list;
}

const BACKGROUND_TEXT: Record<string, string> = {};

function seed(): EventSummary[] {
  const specs = [...demoEvents(), ...backgroundEvents()];
  for (const s of specs) {
    const t = (s as Spec & { _text?: string })._text;
    if (t) BACKGROUND_TEXT[s.event_id] = t;
    delete (s as Spec & { _text?: string })._text;
  }
  specs.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const list = specs.map((s, i) => makeEvent({ ...s, seq: 1000 + i }));
  return withClientRefs(list).sort((a, b) => b.seq - a.seq);
}

export const events = seeded(seed);

// ---------------------------------------------------------------------------------------------------------------
// Traces

const STEP_ORDER: Step[] = ["identity", "normalise", "rules", "similarity", "classifier", "judge", "decide", "approval", "route", "output"];

const DEFAULT_RESULT: Record<Step, string> = {
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

export function buildSteps(e: EventSummary): TraceStep[] {
  const extra = EXTRAS[e.event_id] ?? {};
  const names = STEP_ORDER.filter((s) => s !== "approval" || e.changed_steps.approval);
  return names.map((step) => {
    const changed = Object.prototype.hasOwnProperty.call(e.changed_steps, step);
    const result = changed ? e.changed_steps[step] : step === "identity" && e.agent_id ? "agent identified" : DEFAULT_RESULT[step];
    return { step, result, ms: extra.ms?.[step] ?? null, changed, controls: extra.controls?.[step] ?? [] };
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
    detail: { ...(EXTRAS[e.event_id]?.detail ?? {}) },
    prev_hash: FAKE_HASH(e.seq - 1),
    hash: FAKE_HASH(e.seq),
  };
}

export function buildTrace(e: EventSummary): EventTrace {
  const saw = EXTRAS[e.event_id]?.saw;
  return {
    event: e,
    steps: buildSteps(e),
    model_saw: saw?.text ?? null,
    model_saw_note: saw?.note ?? "",
    record: toAuditEvent(e),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Session transcripts

function turnText(e: EventSummary): string | null {
  const x = EXTRAS[e.event_id];
  return x?.text ?? x?.saw?.text ?? BACKGROUND_TEXT[e.event_id] ?? null;
}

export function buildTranscript(sessionId: string): SessionTranscript | null {
  const list = events.items.filter((e) => e.session_id === sessionId).sort((a, b) => a.seq - b.seq);
  if (list.length === 0) return null;
  const first = list[0];
  const last = list[list.length - 1];
  const role = (p: EventSummary["point"]): SessionTranscript["turns"][number]["role"] =>
    p === "ingress" ? "user" : p === "egress" ? "assistant" : p === "tool_result" ? "tool_result" : p === "tool_call" ? "tool_call" : "system";
  return {
    session_id: sessionId,
    client_ref: last.client_ref ?? first.client_ref,
    subject: first.subject,
    username: first.username,
    groups: first.groups,
    session_label: [...list].reverse().find((e) => e.session_label)?.session_label ?? null,
    started_at: first.client_ref?.started_at ?? first.timestamp,
    last_at: last.timestamp,
    truncated: false,
    turns: list.map((e) => {
      const text = turnText(e);
      return {
        event_id: e.event_id,
        trace_id: e.trace_id,
        seq: e.seq,
        timestamp: e.timestamp,
        point: e.point,
        role: role(e.point),
        text,
        retained: text !== null,
        model: e.model,
        tool: e.tool,
        action: e.action,
        applied: e.applied,
        rule_ids: e.rule_ids,
        summary: e.summary,
      };
    }),
  };
}
