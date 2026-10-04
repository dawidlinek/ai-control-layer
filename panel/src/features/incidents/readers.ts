/**
 * Readers over an incident. Type-specific evidence comes from the typed `Incident.evidence` (discriminated on
 * `kind`, with a plain `summary`). Only when an older gateway sends no `evidence` do the tolerant readers fall back to
 * the free-form `Incident.detail`. What has no typed home (linked traces with descriptions, a timeline of system
 * events, call counters of a rug pull) is still read from `detail`; all of it is optional.
 * Keys the demo uses in `detail` are listed in `src/mocks/db/incidents.ts`.
 */
import type { Incident, IncidentEvidence, IncidentNote } from "@/lib/api/types";

type Detail = Record<string, unknown>;
type EvidenceOf<K extends IncidentEvidence["kind"]> = Extract<IncidentEvidence, { kind: K }>;

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const obj = (v: unknown): Detail | undefined => (v && typeof v === "object" && !Array.isArray(v) ? (v as Detail) : undefined);
const iso = (v: unknown): string | undefined => {
  const s = str(v);
  return s && !Number.isNaN(Date.parse(s)) ? s : undefined;
};

function detailOf(i: Pick<Incident, "detail">): Detail {
  return obj(i.detail) ?? {};
}

const CATEGORY_LABEL: Record<string, string> = {
  mcp_rug_pull: "MCP rug pull",
  budget_breach: "Budget breach",
  rule_of_two: "Rule of Two",
  forbidden_model: "Forbidden model",
  signature_feed: "Signature feed",
  policy_change: "Policy change",
  break_glass: "Break-glass",
  artifact_scan: "Artifact scan",
  plugin_bypass: "Plugin bypass",
  exfiltration_attempt: "Exfiltration attempt",
};

/** Machine kind used to pick actions: the category. */
export function incidentKind(i: Pick<Incident, "category">): string {
  return i.category;
}

/** Human type label: a known category label, or the category humanised. */
export function typeLabel(i: Pick<Incident, "category">): string {
  const label = CATEGORY_LABEL[i.category];
  if (label) return label;
  const h = i.category.replace(/[_-]+/g, " ").trim();
  return h ? h.charAt(0).toUpperCase() + h.slice(1) : "Incident";
}

/** The plain-language summary under the title (written by the gateway's template): `evidence.summary`, else the title. */
export function summaryOf(i: Pick<Incident, "evidence" | "detail" | "title">): string {
  return str(i.evidence?.summary) ?? str(detailOf(i).summary) ?? `${i.title}.`;
}

export type IncidentStatus = Incident["status"];

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  open: "Open",
  triaged: "Triaged",
  resolved: "Resolved",
  false_positive: "False positive",
};

export const isClosed = (s: IncidentStatus) => s === "resolved" || s === "false_positive";

export interface LinkedTrace {
  at: string | null;
  id: string;
  what: string;
}

/** `detail.traces`, else the contract's `event_ids` without descriptions. */
export function tracesOf(i: Pick<Incident, "detail" | "event_ids">): LinkedTrace[] {
  const fromDetail = arr(detailOf(i).traces)
    .map(obj)
    .filter((t): t is Detail => !!t && !!str(t.trace_id))
    .map((t) => ({ at: iso(t.at) ?? null, id: str(t.trace_id)!, what: str(t.what) ?? "" }));
  if (fromDetail.length > 0) return fromDetail;
  return i.event_ids.map((id) => ({ at: null, id, what: "" }));
}

export type TimelineTone = "bad" | "person" | "system";

export interface TimelineEntry {
  at: string;
  who: string;
  text: string;
  tone: TimelineTone;
}

/** System events from `detail.timeline` merged with the notes (people), oldest first. */
export function timelineOf(i: Pick<Incident, "detail" | "notes">): TimelineEntry[] {
  const sys = arr(detailOf(i).timeline)
    .map(obj)
    .filter((t): t is Detail => !!t && !!iso(t.at) && !!str(t.text))
    .map((t): TimelineEntry => {
      const who = str(t.who) ?? "system";
      const tone = t.tone === "bad" ? "bad" : t.tone === "person" || who !== "system" ? "person" : "system";
      return { at: iso(t.at)!, who, text: str(t.text)!, tone };
    });
  const notes = i.notes.map(
    (n: IncidentNote): TimelineEntry => ({ at: n.at, who: n.author, text: n.text, tone: n.author === "system" ? "system" : "person" }),
  );
  return [...sys, ...notes].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

export interface RugPullEvidence {
  server: string;
  tool: string;
  toolId: string;
  approvedHash: string | null;
  approvedAt: string | null;
  newHash: string | null;
  changedAt: string | null;
  diff: { sign: "+" | "-" | "~" | " "; text: string }[];
  findings: string[];
  sessionsListed: number | null;
  callsSinceChange: number | null;
}

function diffLines(text: string | null | undefined): RugPullEvidence["diff"] {
  return (text ?? "")
    .split("\n")
    .filter((l) => l !== "")
    .map((l): RugPullEvidence["diff"][number] => {
      const c = l.charAt(0);
      return c === "+" || c === "-" || c === "~" || c === " " ? { sign: c, text: l.slice(1) } : { sign: " ", text: l };
    });
}

function rugPullFromEvidence(ev: EvidenceOf<"mcp_rug_pull">, d: Detail): RugPullEvidence {
  return {
    server: ev.server,
    tool: ev.tool,
    toolId: ev.tool_id,
    approvedHash: ev.approved_hash,
    approvedAt: ev.approved_at,
    newHash: ev.new_hash,
    changedAt: ev.changed_at,
    diff: diffLines(ev.description_diff),
    findings: ev.findings,
    sessionsListed: num(d.sessions_listed) ?? null,
    callsSinceChange: num(d.calls_since_change) ?? null,
  };
}

/** Fallback for a gateway that sends no `evidence`: the free-form `detail`. */
function rugPullFromDetail(i: Pick<Incident, "subject">, d: Detail): RugPullEvidence {
  const server = str(d.server) ?? (i.subject ?? "").replace(/^MCP server\s+/i, "");
  const tool = str(d.tool) ?? "";
  return {
    server,
    tool,
    toolId: str(d.tool_id) ?? (server && tool ? `${server}.${tool}` : tool),
    approvedHash: str(d.approved_hash) ?? null,
    approvedAt: iso(d.approved_at) ?? null,
    newHash: str(d.new_hash) ?? null,
    changedAt: iso(d.changed_at) ?? null,
    diff: diffLines(str(d.description_diff)),
    findings: arr(d.findings).map(str).filter((f): f is string => !!f),
    sessionsListed: num(d.sessions_listed) ?? null,
    callsSinceChange: num(d.calls_since_change) ?? null,
  };
}

export function rugPullOf(i: Pick<Incident, "evidence" | "detail" | "category" | "subject">): RugPullEvidence | null {
  if (i.evidence) return i.evidence.kind === "mcp_rug_pull" ? rugPullFromEvidence(i.evidence, detailOf(i)) : null;
  return i.category === "mcp_rug_pull" ? rugPullFromDetail(i, detailOf(i)) : null;
}

export type BreakerStateName = "closed" | "open" | "half_open";

export interface BreakerEvidence {
  sessionId: string | null;
  breakerId: string | null;
  /** Null when the breaker is not part of this breach (a soft limit): the state row is hidden. */
  state: BreakerStateName | null;
  halfOpenAt: string | null;
  meter: string;
  used: number | null;
  limit: number | null;
  cause: string | null;
}

const METER_LABEL: Record<string, string> = {
  usd_day: "USD per day",
  usd_month: "USD per month",
  gpu_seconds: "GPU-seconds",
  gpu_seconds_session: "GPU-seconds",
};

export function meterLabel(meter: string): string {
  return METER_LABEL[meter] ?? meter.replace(/_/g, " ");
}

function plus(from: string, seconds: number): string {
  return new Date(Date.parse(from) + seconds * 1000).toISOString();
}

function breakerFromEvidence(ev: EvidenceOf<"budget_breach">, i: Pick<Incident, "created_at">, d: Detail): BreakerEvidence {
  const sessionId = ev.session_id ?? (ev.node?.startsWith("session:") ? ev.node.slice("session:".length) : null);
  const level = ev.level === "loop" ? "runaway signal" : ev.level === "hard" ? "hard limit" : ev.level === "soft" ? "soft limit" : null;
  const cause = [level, ev.action && `action: ${ev.action.replace(/_/g, " ")}`].filter(Boolean).join(", ") || null;
  return {
    sessionId,
    breakerId: sessionId ? `session:${sessionId}` : null,
    state: ev.breaker,
    halfOpenAt: iso(d.half_open_at) ?? (ev.breaker === "open" && ev.cooldown_s ? plus(i.created_at, ev.cooldown_s) : null),
    meter: ev.meter ? meterLabel(ev.meter) : "GPU-seconds",
    used: ev.used,
    limit: ev.limit,
    cause,
  };
}

/** Fallback for a gateway that sends no `evidence`: the free-form `detail`. */
function breakerFromDetail(d: Detail): BreakerEvidence {
  const sessionId = str(d.session_id) ?? null;
  const state = d.breaker === "closed" || d.breaker === "half_open" ? d.breaker : "open";
  return {
    sessionId,
    breakerId: str(d.breaker_id) ?? (sessionId ? `session:${sessionId}` : null),
    state,
    halfOpenAt: iso(d.half_open_at) ?? null,
    meter: str(d.meter) ?? "GPU-seconds",
    used: num(d.used) ?? num(d.gpu_seconds_used) ?? null,
    limit: num(d.limit) ?? num(d.gpu_seconds_limit) ?? null,
    cause: str(d.cause) ?? null,
  };
}

export function breakerOf(i: Pick<Incident, "evidence" | "detail" | "category" | "created_at">): BreakerEvidence | null {
  if (i.evidence) return i.evidence.kind === "budget_breach" ? breakerFromEvidence(i.evidence, i, detailOf(i)) : null;
  return i.category === "budget_breach" ? breakerFromDetail(detailOf(i)) : null;
}

export interface FactRow {
  label: string;
  value: string;
  mono?: boolean;
}

/** A small evidence block for the kinds that have no dedicated section: labelled rows plus optional tags. */
export interface FactsEvidence {
  title: string;
  rows: FactRow[];
  tagsLabel?: string;
  tags: string[];
}

const humanise = (k: string): string => {
  const h = k.replace(/[_-]+/g, " ").trim();
  return h ? h.charAt(0).toUpperCase() + h.slice(1) : k;
};

/** Evidence of the kinds without a dedicated section (everything but rug pull and budget breach), or null. */
export function factsOf(i: Pick<Incident, "evidence">): FactsEvidence | null {
  const ev = i.evidence;
  if (!ev) return null;
  const rows: FactRow[] = [];
  const add = (label: string, value: string | number | boolean | null | undefined, mono = false) => {
    if (value !== null && value !== undefined && value !== "") rows.push({ label, value: String(value), mono });
  };
  switch (ev.kind) {
    case "mcp_tool_poisoning":
    case "mcp_name_collision":
      add("Server · tool", ev.server && ev.tool ? `${ev.server} › ${ev.tool}` : ev.tool_id, true);
      add("Status", ev.status);
      add("Hash", ev.new_hash ? shortHash(ev.new_hash) : null, true);
      return {
        title: ev.kind === "mcp_tool_poisoning" ? "Tool flagged as poisoned" : "Tool name collision",
        rows,
        tagsLabel: "Findings",
        tags: ev.findings,
      };
    case "mcp_protocol_violation":
      add("Server", ev.server, true);
      return { title: "Protocol violations", rows, tagsLabel: "Violations", tags: ev.violations };
    case "canary_triggered":
      add("Tool", ev.tool, true);
      add("Server", ev.server, true);
      add("Canary values redacted", ev.occurrences);
      return { title: "Canary data returned", rows, tags: [] };
    case "forbidden_model":
      add("Model requested", ev.model, true);
      return { title: "Request", rows, tags: [] };
    case "blocked_request":
    case "blocked_response":
      add("Checked at", ev.point, true);
      add("Decided by", ev.decided_by, true);
      return { title: ev.kind === "blocked_request" ? "Request blocked" : "Response blocked", rows, tags: [] };
    case "plugin_bypass":
      add("Tool", ev.tool, true);
      add("Explanation", ev.explanation);
      return { title: "Plugin bypass", rows, tags: [] };
    case "generic":
      for (const [k, v] of Object.entries(ev.facts)) add(humanise(k), v, typeof v !== "string");
      return { title: "Details", rows, tags: [] };
    default:
      return null;
  }
}

export function approvalIdOf(i: Pick<Incident, "detail">): string | null {
  return str(detailOf(i).approval_id) ?? null;
}

export function previousPolicyVersion(i: Pick<Incident, "detail">): string | null {
  return str(detailOf(i).previous_version) ?? null;
}

/** `9c1e…a07b` */
export function shortHash(h: string): string {
  return h.length > 10 ? `${h.slice(0, 4)}…${h.slice(-4)}` : h;
}
