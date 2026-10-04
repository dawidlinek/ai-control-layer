/**
 * Mock data: models domain (connectors + model registry). Demo data from docs/ux/design-reference/ModelsConnectors.dc.html,
 * updated to the HANDOFF section 7.1 lineup (Gemini Flash / Pro in the cloud, local Qwen ~27B, prompt-configured
 * loan-memo specialist, local embeddings + judge). Endpoints: /admin/v1/connectors (+ kill-switch), /admin/v1/models.
 *
 * Demo-only details the contract has no field for (who can use a model, how `auto` picks it, the model file, a one-line
 * description) ride in the free-form `tags` map; the screen reads them with tolerant readers (features/models/details.ts).
 */
import { seeded } from "./registry";
import type { ConnectorStatus, ModelInfo } from "./types";

function seedConnectors(): ConnectorStatus[] {
  return [
    {
      id: "local",
      type: "openai_compatible",
      tier: "local",
      enabled: true,
      kill_switch: false,
      healthy: true,
      latency_ms_p50: 210,
      last_error: null,
      spend_usd_day: 0,
    },
    {
      id: "local-pl",
      type: "openai_compatible",
      tier: "local",
      enabled: true,
      kill_switch: false,
      healthy: true,
      latency_ms_p50: 240,
      last_error: null,
      spend_usd_day: 0,
    },
    {
      id: "gemini",
      type: "openai_compatible",
      tier: "cloud",
      enabled: true,
      kill_switch: false,
      healthy: true,
      latency_ms_p50: 820,
      last_error: null,
      spend_usd_day: 1.98,
    },
  ];
}

const ALL_CLASSES: ModelInfo["data_classes"] = ["public", "internal", "confidential", "restricted"];

function model(m: Partial<ModelInfo> & Pick<ModelInfo, "id" | "connector" | "tier">): ModelInfo {
  return {
    aliases: [],
    tags: {},
    data_classes: [],
    pricing: {},
    artifact_status: "n/a",
    enabled: true,
    available: true,
    role: null,
    requests_day: 0,
    tokens_in_day: 0,
    tokens_out_day: 0,
    usd_day: 0,
    gpu_seconds_day: 0,
    ...m,
  };
}

function seedModels(): ModelInfo[] {
  return [
    model({
      id: "gemini/flash",
      connector: "gemini",
      tier: "cloud",
      aliases: ["smart"],
      role: "fast cloud · default for normal work",
      data_classes: ["public", "internal"],
      pricing: { in_per_1k: 0.0003, out_per_1k: 0.0025 },
      requests_day: 251,
      tokens_in_day: 412_000,
      tokens_out_day: 96_000,
      usd_day: 1.42,
      tags: {
        family: "gemini",
        about:
          "Google Gemini Flash through its OpenAI-compatible API. The default for normal work when the data allows it; anything confidential is routed to a local model instead.",
        limit: "LOCK-01: never confidential or restricted",
        who: "operations=group;security=group;Jan Kowalski=grant g-0412 · 23 h left;developers=no · grant only",
        auto_share: "41%",
        auto_reasons: "complexity up to 0.6, public or internal data=212;asked for smart directly=39",
      },
    }),
    model({
      id: "gemini/pro",
      connector: "gemini",
      tier: "cloud",
      aliases: ["smart-pro"],
      role: "strong cloud · complex requests",
      data_classes: ["public", "internal"],
      pricing: { in_per_1k: 0.00125, out_per_1k: 0.01 },
      requests_day: 38,
      tokens_in_day: 61_000,
      tokens_out_day: 22_000,
      usd_day: 0.56,
      tags: {
        family: "gemini",
        about:
          "Google Gemini Pro, the stronger cloud model. auto picks it when a request is complex and the data may leave the company.",
        limit: "LOCK-01: never confidential or restricted",
        who: "security=group;everyone=through auto",
        auto_share: "9%",
        auto_reasons: "complexity above 0.6, public or internal data=31;asked for smart-pro directly=7",
      },
    }),
    model({
      id: "local/qwen3.8-27b",
      connector: "local",
      tier: "local",
      aliases: ["local", "fast"],
      role: "local · all confidential work",
      data_classes: ALL_CLASSES,
      pricing: { usd_per_gpu_second: 0.0006, gpu_seconds_per_1k_tokens: 0.5 },
      artifact_status: "scanned_ok",
      requests_day: 1_034,
      tokens_in_day: 1_210_000,
      tokens_out_day: 330_000,
      gpu_seconds_day: 1_230,
      tags: {
        family: "qwen",
        about:
          "Qwen ~27B on the company GPU server. Everything confidential goes here: confidential data, confidential sessions and confidential repositories. It is also the fallback when Gemini is off.",
        limit: "4-bit, 32k context",
        who: "everyone=through auto;developers=group;credit-analysts=group",
        auto_share: "43%",
        auto_reasons: "confidential data → local only=264;session is confidential (SEC-SESSION-01)=118;Gemini off or budget used up=0",
        model_file: "qwen3.8-27b-instruct-q4_k_m.gguf",
      },
    }),
    model({
      id: "local/bielik",
      connector: "local-pl",
      tier: "local",
      aliases: ["bielik"],
      role: "local · Polish language specialist",
      data_classes: ALL_CLASSES,
      pricing: { usd_per_gpu_second: 0.0006, gpu_seconds_per_1k_tokens: 0.5 },
      artifact_status: "scanned_ok",
      requests_day: 58,
      tokens_in_day: 71_000,
      tokens_out_day: 19_000,
      gpu_seconds_day: 64,
      tags: {
        family: "bielik",
        task: "polish_legal",
        about:
          "Bielik on its own local server, built for Polish. auto picks it for Polish legal texts (contracts, regulations, civil code questions); you can also choose it by name. Confidential data stays on company servers either way.",
        limit: "picked when task score ≥ 0.50",
        who: "everyone=through auto;developers=group;credit-analysts=group;operations=group",
        auto_share: "3%",
        auto_reasons: "Polish legal text (≥ 0.50)=41;asked for bielik directly=17",
        model_file: "bielik-11b-instruct-q4_k_m.gguf",
      },
    }),
    model({
      id: "local/loan-memo",
      connector: "local",
      tier: "local",
      aliases: [],
      role: "loan memo specialist · prompt-configured on Qwen",
      data_classes: ["public", "internal", "confidential"],
      pricing: { usd_per_gpu_second: 0.0006, gpu_seconds_per_1k_tokens: 0.3 },
      artifact_status: "scanned_ok",
      requests_day: 96,
      tokens_in_day: 140_000,
      tokens_out_day: 38_000,
      gpu_seconds_day: 152,
      tags: {
        task: "loan_memo",
        about:
          "The local Qwen with a fixed credit-analyst prompt. auto picks it when it recognises a loan memo task; it writes the memo in English from a pseudonymised application.",
        limit: "picked when task score ≥ 0.80",
        who: "credit-analysts=group;skill/loan-memo-summary=skill",
        auto_share: "7%",
        auto_reasons: "loan memo task (≥ 0.80)=96",
        model_file: "qwen3.8-27b-instruct-q4_k_m.gguf",
      },
    }),
    model({
      id: "local/embed",
      connector: "local",
      tier: "local",
      role: "embeddings (similarity, insights)",
      data_classes: ALL_CLASSES,
      pricing: { usd_per_gpu_second: 0.0006 },
      artifact_status: "scanned_ok",
      requests_day: 2_104,
      gpu_seconds_day: 60,
      tags: { guard: "embeddings", about: "bge-m3 · similarity check against known attacks and Automation Insights", model_file: "bge-m3.gguf" },
    }),
    model({
      id: "local/judge",
      connector: "local",
      tier: "local",
      role: "judge",
      data_classes: ALL_CLASSES,
      pricing: { usd_per_gpu_second: 0.0006 },
      artifact_status: "scanned_ok",
      requests_day: 74,
      gpu_seconds_day: 120,
      tags: { guard: "judge", about: "reuses the local Qwen with judge prompts · about 5–6 % of requests", model_file: "qwen3.8-27b-instruct-q4_k_m.gguf" },
    }),
  ];
}

export const connectors = seeded(seedConnectors);
export const models = seeded(seedModels);
