/**
 * Tolerant readers for `InsightCluster`. `draft_skill` is a free-form map in the contract; the keys used here are
 * documented in src/mocks/db/insights.ts. Missing keys fall back to derived values or are left out.
 */
import { ApiError } from "@/lib/api/client";
import type { InsightCluster } from "@/lib/api/types";

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v : null);
const numOr = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export interface DraftSkill {
  name: string;
  template: string | null;
  inputs: string[];
  model: string | null;
  preset: string | null;
  rules: string | null;
  example: Record<string, string>;
  facts: Array<[string, string]>;
  runs30d: number | null;
  costBefore: string | null;
  costNow: string | null;
  publishedVersion: string | null;
}

function slug(label: string): string {
  return label
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);
}

export function draftOf(c: InsightCluster): DraftSkill {
  const d = (c.draft_skill ?? {}) as Record<string, unknown>;
  const example: Record<string, string> = {};
  if (d.example && typeof d.example === "object") {
    for (const [k, v] of Object.entries(d.example as Record<string, unknown>)) if (typeof v === "string") example[k] = v;
  }
  const facts = Array.isArray(d.facts)
    ? (d.facts as unknown[]).filter((f): f is [string, string] => Array.isArray(f) && typeof f[0] === "string" && typeof f[1] === "string")
    : [];
  return {
    name: str(d.name) ?? `skill/${slug(c.label)}`,
    template: str(d.template),
    inputs: Array.isArray(d.inputs) ? (d.inputs as unknown[]).filter((x): x is string => typeof x === "string") : [],
    model: str(d.model),
    preset: str(d.preset),
    rules: str(d.rules),
    example,
    facts,
    runs30d: numOr(d.runs_30d),
    costBefore: str(d.cost_before),
    costNow: str(d.cost_now),
    publishedVersion: str(d.published_version),
  };
}

/** `{placeholder}` names in a template, in order, without duplicates. */
export function placeholdersOf(template: string): string[] {
  return [...new Set([...template.matchAll(/\{([a-zA-Z_][\w]*)\}/g)].map((m) => m[1]))];
}

export type TemplatePart = { text: string } | { name: string; value: string | null };

/** Split a template into text and placeholders, filling in example values when given. */
export function fillTemplate(template: string, values: Record<string, string> = {}): TemplatePart[] {
  const parts: TemplatePart[] = [];
  let last = 0;
  for (const m of template.matchAll(/\{([a-zA-Z_][\w]*)\}/g)) {
    if (m.index! > last) parts.push({ text: template.slice(last, m.index) });
    parts.push({ name: m[1], value: values[m[1]] ?? null });
    last = m.index! + m[0].length;
  }
  if (last < template.length) parts.push({ text: template.slice(last) });
  return parts;
}

/** "~14 times a day", "every day", "every week", "now and then". `size` = occurrences in the last 30 days. */
export function howOften(c: InsightCluster): string {
  if (c.recurrence === "daily") {
    const perDay = Math.round(c.size / 30);
    return perDay >= 2 ? `~${perDay} times a day` : "every day";
  }
  if (c.recurrence === "weekly") {
    const perWeek = Math.round(c.size / 4);
    return perWeek >= 2 ? `~${perWeek} times a week` : "every week";
  }
  return "now and then";
}

function minutesText(min: number): string {
  if (min >= 60) {
    return `${Math.round(min / 30) / 2} h`;
  }
  return `${Math.round(min)} min`;
}

/** "~25 min a day"; weekly tasks are shown per week ("~1 h a week"). */
export function timeItTakes(c: InsightCluster): string {
  if (c.est_minutes_per_day <= 0) return "—";
  return c.recurrence === "weekly" ? `~${minutesText(c.est_minutes_per_day * 7)} a week` : `~${minutesText(c.est_minutes_per_day)} a day`;
}

export interface SpecialistInfo {
  id: string;
  base: string | null;
  method: string | null;
  memosToday: number | null;
  savedPerMemo: number | null;
  savedMonth: number | null;
  evaluation: Array<{ model: string; quality: string; formatOk: string; p95: string; cost: string; current: boolean }>;
  examples: number;
  cluster: InsightCluster;
}

/** The specialist model (if any) described on a cluster's draft skill. */
export function specialistOf(clusters: readonly InsightCluster[]): SpecialistInfo | null {
  for (const c of clusters) {
    const d = (c.draft_skill ?? {}) as Record<string, unknown>;
    const s = d.specialist as Record<string, unknown> | undefined;
    if (!s || typeof s !== "object" || !str(s.id)) continue;
    const evaluation = Array.isArray(d.evaluation)
      ? (d.evaluation as Array<Record<string, unknown>>)
          .filter((e) => e && typeof e === "object" && str(e.model))
          .map((e) => ({
            model: String(e.model),
            quality: str(e.quality) ?? "—",
            formatOk: str(e.format_ok) ?? "—",
            p95: str(e.p95) ?? "—",
            cost: str(e.cost) ?? "—",
            current: e.current === true,
          }))
      : [];
    return {
      id: String(s.id),
      base: str(s.base),
      method: str(s.method),
      memosToday: numOr(s.memos_today),
      savedPerMemo: numOr(s.gpu_seconds_saved_per_memo),
      savedMonth: numOr(s.gpu_seconds_saved_month),
      evaluation,
      examples: c.size,
      cluster: c,
    };
  }
  return null;
}

/** The gateway does not serve Insights (501 "not implemented yet", or 404): an empty state, not an error. */
export function isNotSwitchedOn(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 501 || error.status === 404);
}
