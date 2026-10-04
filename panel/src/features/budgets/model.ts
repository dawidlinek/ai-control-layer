/**
 * Tolerant readers for `BudgetNode`. The contract only has `limits` / `usage` maps (meter -> number); forecasts,
 * hourly spend, the split by model and where a limit is set are read from extra `usage` keys when the gateway
 * sends them (see src/mocks/db/budgets.ts for the key convention) and simply left out when it does not.
 */
import type { BreakerState, BudgetNode } from "@/lib/api/types";
import { formatNumber, formatUsd } from "@/lib/format";

export type Period = "today" | "month";
export type Unit = "usd" | "gpu_seconds";

const PERIOD_SUFFIX: Record<Period, string> = { today: "day", month: "month" };

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** The node's main meter: USD when it has a USD meter, else GPU-seconds. */
export function unitOf(node: BudgetNode): Unit {
  const keys = [...Object.keys(node.limits), ...Object.keys(node.usage)];
  return keys.some((k) => k === "usd_day" || k === "usd_month") ? "usd" : "gpu_seconds";
}

export function meterKey(node: BudgetNode, period: Period, unit: Unit = unitOf(node)): string {
  return `${unit}_${PERIOD_SUFFIX[period]}`;
}

export function usedOf(node: BudgetNode, period: Period, unit?: Unit): number {
  return num(node.usage[meterKey(node, period, unit)]) ?? 0;
}

export function limitOf(node: BudgetNode, period: Period, unit?: Unit): number | null {
  return num(node.limits[meterKey(node, period, unit)]);
}

export function forecastOf(node: BudgetNode, period: Period, unit?: Unit): number | null {
  return num(node.usage[`forecast.${meterKey(node, period, unit)}`]);
}

/** Spend per hour today (index 0 = 00:00), in the node's unit. Empty when the gateway does not send it. */
export function hoursOf(node: BudgetNode): number[] {
  const out: number[] = [];
  for (let i = 0; i < 24; i++) {
    const v = num(node.usage[`hour.${i}`]);
    if (v === null) break;
    out.push(v);
  }
  return out;
}

export interface ModelUse {
  model: string;
  value: number;
  unit: Unit;
}

/** Cloud models are billed in USD, local ones (and guards) in GPU-seconds. */
export const unitOfModel = (model: string): Unit => (model.startsWith("gemini/") || model.startsWith("cloud/") ? "usd" : "gpu_seconds");

export function modelsOf(node: BudgetNode, period: Period): ModelUse[] {
  const prefix = `model.${PERIOD_SUFFIX[period]}.`;
  return Object.entries(node.usage)
    .filter(([k]) => k.startsWith(prefix))
    .map(([k, v]) => ({ model: k.slice(prefix.length), value: Number(v), unit: unitOfModel(k.slice(prefix.length)) }))
    .sort((a, b) => (a.unit === b.unit ? b.value - a.value : a.unit === "usd" ? -1 : 1));
}

export function formatAmount(value: number, unit: Unit): string {
  return unit === "usd" ? formatUsd(value) : formatNumber(Math.round(value));
}

export function formatWithUnit(value: number, unit: Unit): string {
  return `${formatAmount(value, unit)} ${unit === "usd" ? "USD" : "GPU-s"}`;
}

export interface LimitSource {
  label: string;
  href: string;
}

/** Where the limit comes from: a budgets.yaml line or a grant. */
export function sourceOf(node: BudgetNode): LimitSource {
  const grant = num(node.usage["meta.grant"]);
  if (grant !== null) {
    const id = `g-${String(grant).padStart(4, "0")}`;
    return { label: `grant ${id}`, href: `/grants?sel=${id}` };
  }
  const line = num(node.usage["meta.yaml_line"]);
  return {
    label: line !== null ? `budgets.yaml L${line}` : "budgets.yaml",
    href: `/policies?tab=yaml&file=budgets.yaml${line !== null ? `&line=${line}` : ""}`,
  };
}

/** Last segment of the node id: `group:developers` -> `developers`. */
export const keyOf = (node: BudgetNode) => node.id.slice(node.id.indexOf(":") + 1);

export const KIND_LABEL: Record<BudgetNode["level"], string> = {
  org: "org",
  group: "group",
  user: "person",
  agent: "agent",
  session: "agent session",
};

export function nameOf(node: BudgetNode, displayName: (username: string) => string): string {
  switch (node.level) {
    case "org":
      return "Whole company";
    case "user":
      return displayName(keyOf(node));
    case "session":
      return `session ${keyOf(node)}`;
    default:
      return keyOf(node);
  }
}

export interface TreeRow {
  node: BudgetNode;
  depth: number;
}

/** Depth-first order: company -> groups -> people / agent -> session. Orphans (unknown parent) go to the top level. */
export function flattenTree(nodes: readonly BudgetNode[]): TreeRow[] {
  const ids = new Set(nodes.map((n) => n.id));
  const children = new Map<string | null, BudgetNode[]>();
  for (const n of nodes) {
    const p = n.parent && ids.has(n.parent) ? n.parent : null;
    children.set(p, [...(children.get(p) ?? []), n]);
  }
  const out: TreeRow[] = [];
  const walk = (parent: string | null, depth: number) => {
    for (const n of children.get(parent) ?? []) {
      out.push({ node: n, depth });
      walk(n.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

export type BreakerView = "open" | "half_open" | "alert" | "closed" | "none";

/** Breaker column: open / half-open from the breaker; "alert at 80%" when closed but at or above 80 % of the limit. */
export function breakerView(node: BudgetNode, period: Period): BreakerView {
  const b: BreakerState | null = node.breaker;
  if (b?.state === "open") return "open";
  if (b?.state === "half_open") return "half_open";
  const limit = limitOf(node, period);
  if (limit && usedOf(node, period) / limit >= 0.8) return "alert";
  return b ? "closed" : "none";
}

/** Requests of this node in Traffic. */
export function trafficHref(node: BudgetNode): string {
  switch (node.level) {
    case "org":
      return "/traffic";
    case "group":
      return `/traffic?group=${encodeURIComponent(keyOf(node))}`;
    default:
      return `/traffic?q=${encodeURIComponent(keyOf(node))}`;
  }
}

export function endOfMonthLabel(now = new Date()): string {
  const last = new Date(now.getFullYear(), now.getMonth() + 1, 0);
  return `${last.getDate()} ${last.toLocaleString("en-GB", { month: "short" })}`;
}
