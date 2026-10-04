/**
 * Pure helpers for the Traffic screen and the session view: labels, filters, readers for demo-only fields.
 * Everything here tolerates missing data (the real gateway may not send the free-form `detail` keys).
 */
import type { components } from "@/lib/api/schema";
import type { EventSummary, SessionLabelInfo } from "@/lib/api/types";
import { DECISIONS, type Decision } from "@/lib/decisions";
import { formatClock } from "@/lib/format";

export type InspectionPoint = components["schemas"]["InspectionPoint"];
export type DataClass = components["schemas"]["DataClass"];

export const RANGES = ["15m", "1h", "24h", "7d"] as const;
export type Range = (typeof RANGES)[number];
export const RANGE_LABEL: Record<Range, string> = {
  "15m": "Last 15 minutes",
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
};
const RANGE_MS: Record<Range, number> = { "15m": 15 * 60_000, "1h": 3_600_000, "24h": 86_400_000, "7d": 7 * 86_400_000 };

export function sinceFor(range: Range, now = Date.now()): string {
  return new Date(now - RANGE_MS[range]).toISOString();
}

/** The points the Point filter offers (prompt / answer / tool call / tool result / tool list). */
export const POINTS = ["ingress", "egress", "tool_call", "tool_result", "mcp_tools_list"] as const satisfies readonly InspectionPoint[];

const POINT_LABEL: Record<InspectionPoint, string> = {
  ingress: "prompt",
  egress: "answer",
  tool_call: "tool call",
  tool_result: "tool result",
  mcp_tools_list: "tool list",
  mcp_initialize: "MCP connect",
  embeddings: "embeddings",
  agent_message: "agent message",
  artifact_load: "model file",
};

export function pointLabel(p: InspectionPoint | null | undefined): string {
  return p ? POINT_LABEL[p] : "—";
}

export const DATA_CLASSES = ["public", "internal", "confidential", "restricted"] as const satisfies readonly DataClass[];
export const GROUPS = ["developers", "credit-analysts", "operations", "security", "agents"] as const;

const CLIENT_LABEL: Record<string, string> = { librechat: "LibreChat", opencode: "OpenCode", agent: "agent", mcp: "MCP" };

/** People directory: username -> display name (from `/users`); falls back to the username. */
export type NameOf = (username: string | null | undefined) => string;

export function whoName(e: Pick<EventSummary, "username" | "agent_id" | "subject">, nameOf: NameOf): string {
  if (e.agent_id) return e.agent_id;
  return e.username ? nameOf(e.username) : (e.subject ?? "unknown");
}

/** Second line of the Who cell: "LibreChat · credit-analysts", "agent · session s_77c1", "MCP docs-search". */
export function clientLine(e: EventSummary): string {
  if (e.client_app === "mcp") {
    const server = e.tool?.split(".")[0];
    return server ? `MCP ${server}` : "MCP";
  }
  if (e.client_app === "agent" || e.agent_id) return e.session_id ? `agent · session ${e.session_id}` : "agent";
  const client = e.client_app ? (CLIENT_LABEL[e.client_app] ?? e.client_app) : null;
  return [client, e.groups[0]].filter(Boolean).join(" · ") || "—";
}

/** The decisions of an event, in order (`applied` when present, else the final `action`). */
export function decisionsOf(e: Pick<EventSummary, "applied" | "action">): Decision[] {
  if (e.applied.length) return e.applied;
  return e.action ? [e.action] : [];
}

export function isAllowedOnly(e: Pick<EventSummary, "applied" | "action">): boolean {
  const d = decisionsOf(e);
  return d.length > 0 && d.every((x) => x === "allow");
}

/**
 * Model or tool for the table cell and the trace sidebar: the model, else the gateway's `tool_preview`
 * ("bash: git push origin main"), else the bare tool name.
 */
export function modelOrTool(e: Pick<EventSummary, "model" | "tool" | "tool_preview">): string {
  return e.model ?? e.tool_preview ?? e.tool ?? "—";
}

export function riskLabel(score: number | null | undefined): string {
  if (score == null) return "—";
  const band = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  return `${score.toFixed(2)} · ${band}`;
}

/** Sessions that are confidential or restricted carry the label chip ("local only"). */
export function isSensitiveLabel(l: SessionLabelInfo | null | undefined): l is SessionLabelInfo {
  return !!l && (l.data_class === "confidential" || l.data_class === "restricted");
}

/** "Session confidential since 14:03 · local only" (HANDOFF 7.2). */
export function sessionLabelText(l: SessionLabelInfo): string {
  const parts = [`Session ${l.data_class}${l.since ? ` since ${formatClock(l.since)}` : ""}`];
  if (l.trust === "untrusted") parts.push("untrusted content");
  if (l.local_only) parts.push("local only");
  return parts.join(" · ");
}

export const RULE_ID_RE = /^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$/;

// ---------------------------------------------------------------------------------------------------------------
// Filters

export interface TrafficFilters {
  range: Range;
  decision: Decision[];
  who: string | null;
  point: InspectionPoint[];
  group: string | null;
  dataClass: DataClass[];
  q: string;
  hideAllowed: boolean;
}

/** Query params the events endpoint understands (the rest is filtered client-side). */
export function serverParams(f: TrafficFilters) {
  const q = f.q.trim();
  return {
    range: f.range,
    subject: f.who ?? undefined,
    group: f.group ?? undefined,
    action: f.decision.length === 1 ? f.decision[0] : undefined,
    point: f.point.length === 1 ? f.point[0] : undefined,
    rule_id: RULE_ID_RE.test(q) ? q : undefined,
  };
}

/** Client-side part of the filters (multi-selects, hide allowed, data class, text search). */
export function matchesFilters(e: EventSummary, f: TrafficFilters, nameOf: NameOf = (u) => u ?? ""): boolean {
  if (f.hideAllowed && isAllowedOnly(e)) return false;
  if (f.decision.length && !decisionsOf(e).some((d) => f.decision.includes(d))) return false;
  if (f.point.length && !(e.point && f.point.includes(e.point))) return false;
  if (f.dataClass.length && !(e.data_class && f.dataClass.includes(e.data_class))) return false;
  if (f.who && e.username !== f.who && e.subject !== f.who) return false;
  if (f.group && !e.groups.includes(f.group)) return false;
  const q = f.q.trim().toLowerCase();
  if (q) {
    const hay = [
      e.event_id,
      e.trace_id,
      e.session_id,
      e.username,
      e.username ? nameOf(e.username) : null,
      e.agent_id,
      e.model,
      e.tool,
      e.tool_preview,
      e.summary,
      ...e.rule_ids,
    ];
    if (!hay.some((v) => v?.toLowerCase().includes(q))) return false;
  }
  return true;
}

export function isDecision(v: string): v is Decision {
  return (DECISIONS as readonly string[]).includes(v);
}

// ---------------------------------------------------------------------------------------------------------------
// Redacted text: split into plain text and placeholder chips.

/** `<PESEL_1>`, `<PERSON_1>`, `‹SECRET:api_key›`, `[removed: …]`. */
const PLACEHOLDER_RE = /(<[A-Z][A-Z_]*_\d+>|‹[^›]+›|\[removed:[^\]]*\])/g;

export interface TextPart {
  text: string;
  placeholder: boolean;
}

export function splitPlaceholders(text: string): TextPart[] {
  return text
    .split(PLACEHOLDER_RE)
    .filter((t) => t !== "")
    .map((t) => ({ text: t, placeholder: /^(<[A-Z][A-Z_]*_\d+>|‹[^›]+›|\[removed:[^\]]*\])$/.test(t) }));
}
