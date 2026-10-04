/**
 * Mock data: budgets domain (`/admin/v1/budgets`, `/admin/v1/budgets/breakers`, reset).
 * Demo data from docs/ux/design-reference/Budgets.dc.html, adapted to the HANDOFF 7.1 model lineup.
 *
 * The contract's `BudgetNode` has only `limits` / `usage` maps (meter -> number). Everything else the design
 * shows travels as extra keys in `usage`, which the Budgets screen reads tolerantly (the real gateway may omit them):
 *   usd_day, usd_month, gpu_seconds_day, gpu_seconds_month     meters (same keys in `limits`)
 *   forecast.<meter>                                           forecast for the end of the period
 *   hour.<0..13>                                               spend per hour today, in the node's main unit
 *   model.day.<model id> / model.month.<model id>              split by model (USD for cloud, GPU-s for local)
 *   saved.usd_day, saved.usd_month, saved.pct                  org only: saved vs sending everything to the cloud
 *   guards.gpu_seconds_day, guards.pct_month                   org only
 *   meta.yaml_line, meta.grant                                 where the limit is set (budgets.yaml line / grant number)
 */
import { inSeconds, minutesAgo } from "../time";
import { seeded } from "./registry";
import type { BudgetNode } from "./types";

type Meter = "usd" | "gpu_seconds";

interface NodeSeed {
  id: string;
  level: BudgetNode["level"];
  parent: string | null;
  meter: Meter;
  day: [used: number, limit: number | null, forecast: number | null];
  month: [used: number, limit: number | null, forecast: number | null];
  hours: number[];
  modelsDay: Record<string, number>;
  modelsMonth: Record<string, number>;
  yamlLine?: number;
  grant?: number;
  extra?: Record<string, number>;
  breaker?: "closed" | "open";
}

const SEEDS: NodeSeed[] = [
  {
    id: "org", level: "org", parent: null, meter: "usd",
    day: [3.12, 5, 4.4], month: [71.2, 100, 74.8],
    hours: [1, 1, 0, 0, 1, 2, 4, 9, 12, 14, 12, 15, 19, 16],
    modelsDay: { "gemini/pro": 1.92, "gemini/flash": 1.2, "local/qwen3.8-27b": 1_410, "local/loan-memo": 152, guards: 350 },
    modelsMonth: { "gemini/pro": 41.3, "gemini/flash": 29.9, "local/qwen3.8-27b": 30_800, "local/loan-memo": 3_440, guards: 3_060 },
    yamlLine: 2,
    extra: {
      gpu_seconds_day: 1_912, "forecast.gpu_seconds_day": 2_700, gpu_seconds_month: 41_300,
      "saved.usd_day": 4.9, "saved.usd_month": 18.4, "saved.pct": 61,
      "guards.gpu_seconds_day": 350, "guards.pct_month": 7.4, "specialist.gpu_seconds_saved_month": 530,
    },
    breaker: "closed",
  },
  {
    id: "group:developers", level: "group", parent: "org", meter: "usd",
    day: [2.1, 5, 3], month: [48.1, 80, 50.5],
    hours: [0, 0, 0, 0, 0, 1, 2, 6, 9, 10, 8, 11, 14, 12],
    modelsDay: { "gemini/pro": 1.32, "gemini/flash": 0.78, "local/qwen3.8-27b": 700 },
    modelsMonth: { "gemini/pro": 28.4, "gemini/flash": 19.7, "local/qwen3.8-27b": 15_200 },
    yamlLine: 6, breaker: "closed",
  },
  {
    id: "user:j.kowalski", level: "user", parent: "group:developers", meter: "usd",
    day: [0.42, 1, 0.7], month: [9.6, 20, 10.2],
    hours: [0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 1, 2, 4, 3],
    modelsDay: { "gemini/pro": 0.21, "gemini/flash": 0.21, "local/qwen3.8-27b": 120 },
    modelsMonth: { "gemini/pro": 4.8, "gemini/flash": 4.8, "local/qwen3.8-27b": 2_600 },
    grant: 420, breaker: "closed",
  },
  {
    id: "user:p.zielinski", level: "user", parent: "group:developers", meter: "usd",
    day: [1.31, 1.5, 1.95], month: [27.5, 30, 29],
    hours: [0, 0, 0, 0, 0, 0, 1, 3, 4, 5, 4, 6, 7, 6],
    modelsDay: { "gemini/pro": 1.05, "gemini/flash": 0.26, "local/qwen3.8-27b": 90 },
    modelsMonth: { "gemini/pro": 21.9, "gemini/flash": 5.6, "local/qwen3.8-27b": 1_900 },
    grant: 421, breaker: "closed",
  },
  {
    id: "group:credit-analysts", level: "group", parent: "org", meter: "usd",
    day: [0.74, 2, 1.1], month: [16.4, 40, 17.2],
    hours: [0, 0, 0, 0, 0, 0, 1, 2, 3, 3, 2, 3, 4, 3],
    modelsDay: { "gemini/flash": 0.74, "local/qwen3.8-27b": 610, "local/loan-memo": 152 },
    modelsMonth: { "gemini/flash": 16.4, "local/qwen3.8-27b": 12_900, "local/loan-memo": 3_440 },
    yamlLine: 10, breaker: "closed",
  },
  {
    id: "user:a.nowak", level: "user", parent: "group:credit-analysts", meter: "usd",
    day: [0.28, null, 0.4], month: [6.1, null, 6.5],
    hours: [0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 1, 1, 2, 1],
    modelsDay: { "gemini/flash": 0.28, "local/qwen3.8-27b": 210, "local/loan-memo": 61 },
    modelsMonth: { "gemini/flash": 6.1, "local/qwen3.8-27b": 4_400, "local/loan-memo": 1_250 },
    yamlLine: 10,
  },
  {
    id: "agent:research-bot", level: "agent", parent: "group:credit-analysts", meter: "gpu_seconds",
    day: [1_020, null, null], month: [18_400, null, null],
    hours: [0, 0, 0, 0, 0, 0, 0, 2, 3, 3, 2, 4, 8, 6],
    modelsDay: { "local/qwen3.8-27b": 640, guards: 380 },
    modelsMonth: { "local/qwen3.8-27b": 11_800, guards: 6_600 },
    yamlLine: 14,
  },
  {
    id: "session:s_77c1", level: "session", parent: "agent:research-bot", meter: "gpu_seconds",
    day: [120, 120, null], month: [120, 120, null],
    hours: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 18],
    modelsDay: { "local/qwen3.8-27b": 82, guards: 38 },
    modelsMonth: { "local/qwen3.8-27b": 82, guards: 38 },
    yamlLine: 15, breaker: "open",
  },
  {
    id: "group:operations", level: "group", parent: "org", meter: "usd",
    day: [0.21, 1, 0.3], month: [4.9, 20, 5.1],
    hours: [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1],
    modelsDay: { "gemini/flash": 0.21, "local/qwen3.8-27b": 160 },
    modelsMonth: { "gemini/flash": 4.9, "local/qwen3.8-27b": 3_500 },
    yamlLine: 18, breaker: "closed",
  },
  {
    id: "group:security", level: "group", parent: "org", meter: "usd",
    day: [0.07, 1, 0.1], month: [1.8, 20, 1.9],
    hours: [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0],
    modelsDay: { "gemini/flash": 0.07, "local/qwen3.8-27b": 40 },
    modelsMonth: { "gemini/flash": 1.8, "local/qwen3.8-27b": 900 },
    yamlLine: 20, breaker: "closed",
  },
];

const round = (n: number) => Math.round(n * 1000) / 1000;

function toNode(s: NodeSeed): BudgetNode {
  const [dUsed, dLimit, dForecast] = s.day;
  const [mUsed, mLimit, mForecast] = s.month;
  const dayKey = `${s.meter}_day`;
  const monthKey = `${s.meter}_month`;
  const limits: Record<string, number> = {};
  if (dLimit !== null) limits[dayKey] = dLimit;
  if (mLimit !== null) limits[monthKey] = mLimit;
  if (s.id === "org") limits.gpu_seconds_day = 3_600;

  const usage: Record<string, number> = { [dayKey]: dUsed, [monthKey]: mUsed };
  if (dForecast !== null) usage[`forecast.${dayKey}`] = dForecast;
  if (mForecast !== null) usage[`forecast.${monthKey}`] = mForecast;
  const hourSum = s.hours.reduce((a, b) => a + b, 0) || 1;
  s.hours.forEach((h, i) => {
    usage[`hour.${i}`] = round((h / hourSum) * dUsed);
  });
  for (const [m, v] of Object.entries(s.modelsDay)) usage[`model.day.${m}`] = v;
  for (const [m, v] of Object.entries(s.modelsMonth)) usage[`model.month.${m}`] = v;
  if (s.yamlLine) usage["meta.yaml_line"] = s.yamlLine;
  if (s.grant) usage["meta.grant"] = s.grant;
  Object.assign(usage, s.extra);

  const breaker: BudgetNode["breaker"] = s.breaker
    ? s.breaker === "open"
      ? {
          id: s.id,
          state: "open",
          opened_at: minutesAgo(3),
          cooldown_until: inSeconds(4 * 60 + 12),
          reason: "The loop detector stopped this session after the same search ran 3 times in 60 s.",
        }
      : { id: s.id, state: "closed", opened_at: null, cooldown_until: null, reason: null }
    : null;

  return { id: s.id, level: s.level, parent: s.parent, limits, usage, breaker };
}

export const budgetNodes = seeded(() => SEEDS.map(toNode));
