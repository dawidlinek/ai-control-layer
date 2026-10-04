/**
 * Mock data: overview domain (`/admin/v1/metrics/overview`). Demo data from docs/ux/design-reference/Dashboard.dc.html,
 * adapted to the HANDOFF 7.1 model lineup (gemini/flash, gemini/pro, local/qwen3.8-27b, local/loan-memo + guards).
 * The summary is built per window on request, relative to "now", so bucket times are always current.
 * Open incidents / pending approvals are counted from the incidents and approvals mock dbs (read only).
 */
import { approvals } from "./approvals";
import { incidents } from "./incidents";
import type { OverviewSummary } from "./types";

export const OVERVIEW_WINDOWS = ["15m", "1h", "24h", "7d"] as const;
export type OverviewWindow = (typeof OVERVIEW_WINDOWS)[number];

type Series = Record<"allow" | "pseudonymise" | "route_local" | "require_approval" | "block", number[]>;

/** Per-minute decisions of the last 15 minutes, exactly as in the prototype (totals 1 102 / 71 / 64 / 3 / 44). */
const LAST_15: Series = {
  allow: [70, 74, 68, 77, 72, 75, 71, 79, 73, 70, 76, 74, 72, 78, 73],
  pseudonymise: [4, 5, 3, 6, 4, 5, 4, 6, 5, 4, 5, 6, 4, 5, 5],
  route_local: [4, 4, 5, 4, 4, 5, 4, 4, 5, 4, 4, 5, 4, 4, 4],
  require_approval: [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1],
  block: [2, 3, 2, 3, 2, 3, 2, 4, 3, 3, 2, 4, 3, 4, 4],
};

/** Deterministic wobble (no Math.random, so tests and screenshots are stable). */
const wobble = (i: number, k: number) => 1 + 0.18 * Math.sin(i * 1.7 + k) + 0.08 * Math.cos(i * 0.9 + k * 2);

/** Daytime shape for hourly buckets: quiet at night, busy 8-17. */
const dayShape = (hourOfDay: number) => (hourOfDay < 6 ? 0.08 : hourOfDay < 8 ? 0.35 : hourOfDay < 18 ? 1 : hourOfDay < 21 ? 0.4 : 0.15);

function synth(count: number, base: Series, factor: (i: number) => number): Series {
  const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const out = {} as Series;
  (Object.keys(base) as (keyof Series)[]).forEach((k, ki) => {
    const m = mean(base[k]);
    out[k] = Array.from({ length: count }, (_, i) => Math.max(0, Math.round(m * factor(i) * wobble(i, ki))));
  });
  return out;
}

const STEP_MS: Record<OverviewWindow, number> = { "15m": 60_000, "1h": 300_000, "24h": 3_600_000, "7d": 86_400_000 };

function seriesFor(window: OverviewWindow, now: number): Series {
  switch (window) {
    case "15m":
      return LAST_15;
    case "1h":
      return synth(12, LAST_15, () => 5);
    case "24h":
      return synth(24, LAST_15, (i) => 60 * dayShape(new Date(now - (23 - i) * STEP_MS["24h"]).getHours()));
    case "7d":
      return synth(7, LAST_15, (i) => {
        const dow = new Date(now - (6 - i) * STEP_MS["7d"]).getDay();
        return dow === 0 || dow === 6 ? 120 : 520;
      });
  }
}

/** OWASP LLM / agentic top-10 categories over the last 24 h (Top risks). Scaled for other windows. */
const TAXONOMY_24H: Record<string, number> = { LLM02: 128, LLM01: 41, ASI02: 9, ASI04: 3, MCP: 1 };
const TAXONOMY_SCALE: Record<OverviewWindow, number> = { "15m": 0.06, "1h": 0.2, "24h": 1, "7d": 5.4 };

export function buildOverview(window: OverviewWindow): OverviewSummary {
  const now = Date.now();
  const step = STEP_MS[window];
  const series = seriesFor(window, now);
  const count = series.allow.length;
  // Bucket starts aligned to the step, the last bucket is the current one.
  const lastStart = Math.floor(now / step) * step;
  const timeline = Array.from({ length: count }, (_, i) => ({
    start: new Date(lastStart - (count - 1 - i) * step).toISOString(),
    counts: Object.fromEntries((Object.keys(series) as (keyof Series)[]).map((k) => [k, series[k][i]])),
  }));
  const decisions_by_action: Record<string, number> = {};
  for (const b of timeline) for (const [k, v] of Object.entries(b.counts)) decisions_by_action[k] = (decisions_by_action[k] ?? 0) + v;
  const decisions_total = Object.values(decisions_by_action).reduce((a, b) => a + b, 0);

  const open = incidents.items.filter((i) => i.status === "open" || i.status === "triaged");
  const incidents_by_severity: Record<string, number> = {};
  for (const i of open) incidents_by_severity[i.severity] = (incidents_by_severity[i.severity] ?? 0) + 1;

  const scale = TAXONOMY_SCALE[window];
  const top_taxonomy = Object.fromEntries(
    Object.entries(TAXONOMY_24H).map(([k, v]) => [k, Math.max(1, Math.round(v * scale))]),
  );

  return {
    generated_at: new Date(now).toISOString(),
    window,
    posture_score: 0, // in the contract, deliberately not shown (HANDOFF section 2)
    decisions_by_action,
    top_rules: { "SEC-PII-01": 135, "SEC-PI-01": 41, "FEED-PKG-0007": 6, "BUDGET-LOOP-01": 3, "SEC-MCP-01": 1 },
    top_taxonomy,
    external_routing_rate: 0.18,
    spend_usd: 3.12,
    savings_usd_vs_external: 4.9,
    open_incidents: open.length,
    pending_approvals: approvals.items.filter((a) => a.status === "pending").length,
    decisions_total,
    timeline,
    incidents_by_severity,
    cost_by_model: [
      { model: "gemini/pro", tier: "cloud", tokens_in: 142_000, tokens_out: 51_000, usd: 1.92, gpu_seconds: 0, share: 0.14 },
      { model: "gemini/flash", tier: "cloud", tokens_in: 318_000, tokens_out: 94_000, usd: 1.2, gpu_seconds: 0, share: 0.29 },
      { model: "local/qwen3.8-27b", tier: "local", tokens_in: 412_000, tokens_out: 128_000, usd: 0, gpu_seconds: 1_410, share: 0.38 },
      { model: "local/loan-memo", tier: "local", tokens_in: 64_000, tokens_out: 31_000, usd: 0, gpu_seconds: 152, share: 0.07 },
      { model: "guards", tier: "local", tokens_in: 205_000, tokens_out: 6_000, usd: 0, gpu_seconds: 350, share: 0.12 },
    ],
    usd_today: 3.12,
    usd_limit_day: 5,
    usd_forecast_day: 4.4,
    gpu_seconds_today: 1_912,
    gpu_seconds_limit_day: 3_600,
  };
}

export function parseWindow(w: string | null): OverviewWindow {
  return (OVERVIEW_WINDOWS as readonly string[]).includes(w ?? "") ? (w as OverviewWindow) : "24h";
}
