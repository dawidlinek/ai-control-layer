/**
 * Mock data: insights domain (`/admin/v1/insights/clusters`, publish). Demo data from
 * docs/ux/design-reference/Insights.dc.html, adapted to the HANDOFF 7.1 lineup: the loan-memo "specialist" is
 * `local/loan-memo`, the local Qwen with a fixed prompt (no fine-tune, no Bielik).
 *
 * `draft_skill` is a free-form map in the contract. The Insights screen reads these keys tolerantly:
 *   name, template, inputs[], model, rules, preset, example{}, facts[[label, value]], runs_30d, cost_before, cost_now,
 *   published_version, specialist{}, evaluation[] (loan memo only).
 * Examples are masked prompts: placeholders only, never raw personal data.
 */
import { seeded } from "./registry";
import type { InsightCluster } from "./types";

// Fields the real gateway (4B) added; the demo rows only set what the screen shows.
const DEFAULTS = {
  scope: "group",
  first_seen: null,
  last_seen: null,
  active_days: 0,
  runs_per_active_day: 0,
  periodicity: 0,
  structural_similarity: 0,
  data_class: "internal",
  models_used: {},
  cost: null,
  draft_validation: [],
  published_skill: null,
  published_groups: [],
  published_at: null,
  published_by: null,
  published_policy_version: null,
  published_version_id: null,
  dismissed_reason: null,
  updated_at: null,
} satisfies Partial<InsightCluster>;
type SeedCluster = Omit<InsightCluster, keyof typeof DEFAULTS> & Partial<InsightCluster>;

function seed(): InsightCluster[] {
  const rows: SeedCluster[] = [
    {
      id: "ic-0101",
      group: "developers",
      label: "Explain a failing test and suggest a fix",
      size: 420,
      distinct_users: 6,
      recurrence: "daily",
      est_minutes_per_day: 25,
      est_usd_month: 27,
      examples_redacted: [
        "Why does test_monthly_rate fail? <TEST_OUTPUT_1> The function: <CODE_1>",
        "pytest says <TEST_OUTPUT_2>, here is <CODE_2>, what is wrong?",
      ],
      task_card:
        "Developers paste pytest output and the failing function and ask why it fails. The answers follow the same shape: cause, fix, one-line test.",
      draft_skill: {
        name: "skill/explain-test-failure",
        template: "Explain why {test} fails for {code}. Answer with the cause, the fix and a one-line test.",
        inputs: ["test: test output (text)", "code: the function (text)"],
        model: "local/qwen3.8-27b",
        preset: "balanced",
        rules: "preset balanced · no tools",
        example: {
          test: "FAILED tests/test_rates.py::test_monthly_rate - AssertionError: 0.0125 != 0.0124",
          code: "def monthly_rate(apr): return round(apr / 12, 4)",
        },
        facts: [
          ["Typical input", "test output + function"],
          ["Typical output", "cause, fix, test"],
          ["Cost now", "0.90 USD / day on gemini/flash"],
          ["Re-asks", "22% of runs"],
        ],
      },
      status: "new",
    },
    {
      id: "ic-0102",
      group: "credit-analysts",
      label: "Loan application → credit memo",
      size: 270,
      distinct_users: 9,
      recurrence: "daily",
      est_minutes_per_day: 40,
      est_usd_month: 0,
      examples_redacted: ["Prepare a credit memo for <PERSON_1>, PESEL <PESEL_1>, income <AMOUNT_1>, loan <AMOUNT_2> …"],
      task_card:
        "Analysts turn a loan application into a structured credit memo: risk summary, debt-to-income, recommendation. Personal data is pseudonymised before the model sees it.",
      draft_skill: {
        name: "skill/loan-memo-summary",
        template: "Based on the application {application}, write a credit memo with: risk summary, debt-to-income, recommendation. Amounts in {currency}.",
        inputs: ["application: the application (text, personal data masked)", "currency: PLN or EUR"],
        model: "local/loan-memo",
        preset: "strict",
        rules: "preset strict · no tools · personal data pseudonymised",
        example: { application: "<PERSON_1>, <PESEL_1>, net income <AMOUNT_1> / month, loan <AMOUNT_2> over 120 months", currency: "PLN" },
        facts: [
          ["Typical input", "application (personal data masked)"],
          ["Typical output", "credit memo, fixed sections"],
          ["Cost before", "3.9 GPU-s per memo"],
          ["Cost now", "1.4 GPU-s with local/loan-memo"],
        ],
        runs_30d: 212,
        cost_before: "3.9 GPU-s",
        cost_now: "1.4 GPU-s",
        published_version: "v6",
        specialist: {
          id: "local/loan-memo",
          base: "local/qwen3.8-27b",
          method: "fixed system prompt + output format + 6 worked examples",
          memos_today: 96,
          gpu_seconds_saved_per_memo: 2.5,
          gpu_seconds_saved_month: 530,
        },
        evaluation: [
          { model: "local/loan-memo (Qwen + prompt)", quality: "4.3 / 5", format_ok: "98%", p95: "4.1 s", cost: "1.4 GPU-s", current: true },
          { model: "local/qwen3.8-27b (no prompt)", quality: "4.0 / 5", format_ok: "88%", p95: "6.2 s", cost: "3.9 GPU-s" },
          { model: "gemini/pro (synthetic data only)", quality: "4.5 / 5", format_ok: "96%", p95: "3.0 s", cost: "0.004 USD" },
        ],
      },
      status: "published",
    },
    {
      id: "ic-0103",
      group: "operations",
      label: "Translate client letters PL → EN",
      size: 180,
      distinct_users: 5,
      recurrence: "daily",
      est_minutes_per_day: 15,
      est_usd_month: 3.6,
      examples_redacted: ["Translate into English, formal tone: Szanowny Panie <PERSON_1>, w odpowiedzi na pismo z dnia <DATE_1> …"],
      task_card: "Operations staff translate short client letters from Polish into English, keeping the bank’s formal tone.",
      draft_skill: {
        name: "skill/letter-pl-en",
        template: "Translate into formal English, keep the placeholders as they are: {letter}",
        inputs: ["letter: the letter (text, names masked)"],
        model: "local/qwen3.8-27b",
        preset: "balanced",
        rules: "preset balanced · no tools",
        example: { letter: "Szanowny Panie <PERSON_1>, dziękujemy za przesłanie dokumentów." },
        facts: [
          ["Typical input", "letter (names masked)"],
          ["Typical output", "formal English letter"],
          ["Cost now", "0.12 USD / day"],
          ["Re-asks", "9% of runs"],
        ],
      },
      status: "new",
    },
    {
      id: "ic-0104",
      group: "operations",
      label: "Summarise this week’s Jira tickets",
      size: 28,
      distinct_users: 7,
      recurrence: "weekly",
      est_minutes_per_day: 9,
      est_usd_month: 1.2,
      examples_redacted: ["Summarise these tickets as closed / blocked / new: <TICKETS_1>"],
      task_card: "Team leads ask for a summary of the week’s tickets: what closed, what is blocked, what is new.",
      draft_skill: {
        name: "skill/jira-weekly",
        template: "Summarise {tickets} as three short sections: closed, blocked, new.",
        inputs: ["tickets: from the jira MCP server"],
        model: "local/qwen3.8-27b",
        preset: "balanced",
        rules: "preset balanced · jira read only",
        example: { tickets: "OPS-311 closed, OPS-318 blocked (waiting for vendor), OPS-322 new" },
        facts: [
          ["Typical input", "ticket list from jira"],
          ["Typical output", "three short sections"],
          ["Cost before", "0.30 USD per summary"],
          ["Cost now", "0.02 USD local"],
        ],
        runs_30d: 28,
        cost_before: "0.30 USD",
        cost_now: "0.02 USD",
        published_version: "v7",
      },
      status: "published",
    },
  ];
  return rows.map((r) => ({ ...DEFAULTS, ...r }) as InsightCluster);
}

export const insightClusters = seeded(seed);
