/**
 * Typed, tolerant readers over `Incident.detail` (a free-form map in the contract; API gap: no typed evidence
 * per category). Every reader accepts missing or wrongly typed keys and falls back to what the contract has.
 * Keys the demo uses are listed in `src/mocks/db/incidents.ts`.
 */
import type { Incident, IncidentNote } from "@/lib/api/types";

type Detail = Record<string, unknown>;

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

/** Machine kind used to pick evidence and actions: `detail.kind`, else the category. */
export function incidentKind(i: Pick<Incident, "detail" | "category">): string {
  return str(detailOf(i).kind) ?? i.category;
}

/** Human type label: `detail.type_label`, a known category label, or the category humanised. */
export function typeLabel(i: Pick<Incident, "detail" | "category">): string {
  const label = str(detailOf(i).type_label) ?? CATEGORY_LABEL[i.category];
  if (label) return label;
  const h = i.category.replace(/[_-]+/g, " ").trim();
  return h ? h.charAt(0).toUpperCase() + h.slice(1) : "Incident";
}

/** The plain-language summary under the title (written by the gateway's template), else the title. */
export function summaryOf(i: Pick<Incident, "detail" | "title">): string {
  return str(detailOf(i).summary) ?? `${i.title}.`;
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

export function rugPullOf(i: Pick<Incident, "detail" | "category" | "subject">): RugPullEvidence | null {
  if (incidentKind(i) !== "mcp_rug_pull") return null;
  const d = detailOf(i);
  const server = str(d.server) ?? (i.subject ?? "").replace(/^MCP server\s+/i, "") ?? "";
  const tool = str(d.tool) ?? "";
  const diff = (str(d.description_diff) ?? "")
    .split("\n")
    .filter((l) => l !== "")
    .map((l): RugPullEvidence["diff"][number] => {
      const c = l.charAt(0);
      return c === "+" || c === "-" || c === "~" || c === " " ? { sign: c, text: l.slice(1) } : { sign: " ", text: l };
    });
  return {
    server,
    tool,
    toolId: str(d.tool_id) ?? (server && tool ? `${server}.${tool}` : tool),
    approvedHash: str(d.approved_hash) ?? null,
    approvedAt: iso(d.approved_at) ?? null,
    newHash: str(d.new_hash) ?? null,
    changedAt: iso(d.changed_at) ?? null,
    diff,
    findings: arr(d.findings).map(str).filter((f): f is string => !!f),
    sessionsListed: num(d.sessions_listed) ?? null,
    callsSinceChange: num(d.calls_since_change) ?? null,
  };
}

export type BreakerStateName = "closed" | "open" | "half_open";

export interface BreakerEvidence {
  sessionId: string | null;
  breakerId: string | null;
  state: BreakerStateName;
  halfOpenAt: string | null;
  meter: string;
  used: number | null;
  limit: number | null;
  cause: string | null;
}

export function breakerOf(i: Pick<Incident, "detail" | "category">): BreakerEvidence | null {
  if (incidentKind(i) !== "budget_breach") return null;
  const d = detailOf(i);
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
