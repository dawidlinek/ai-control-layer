/**
 * MSW handlers: policy (status, schema, files, validate, dry-run, versions, rollback).
 * Writes mutate ../db/policy.ts (new version, status update) so the UI shows the result.
 * Errors follow the gateway: `ErrorResponse` bodies (`{ error, message, details }`) for 404 / 409 / 422.
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import type { components } from "@/lib/api/schema";
import { asList, asStr, isMap, tryParseYamlMap, type YamlMap } from "@/features/policies/yaml-lite";
import { commitPolicyVersion, currentFiles, policyDb, policyStatus } from "../db/policy";
import { adminPath, intParam, MOCK_USER, queryOf } from "./helpers";

type S = components["schemas"];
type PolicyError = S["PolicyError"];

function errorResponse(status: number, error: string, message: string, details: Record<string, unknown> = {}) {
  return HttpResponse.json({ error, message, details } satisfies S["ErrorResponse"], { status });
}

// ---------------------------------------------------------------- JSON Schema (abridged copy of contracts/policy.schema.json)

const ID = { type: "string", pattern: "^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$", description: "Stable rule/control identifier, e.g. SEC-PII-01." };
const ACTIONS = ["allow", "monitor", "redact", "pseudonymise", "sanitize", "route_local", "downgrade", "require_approval", "block"];
const POINTS = ["ingress", "egress", "tool_call", "tool_result", "embeddings", "agent_message", "artifact_load", "mcp_initialize", "mcp_tools_list"];
const PRESETS = ["monitor", "balanced", "strict", "paranoid"];
const COST_TIERS = ["deterministic", "similarity", "l1", "l2"];
const MODES = ["enforce", "monitor"];
const TOP_LEVEL = ["$schema", "version", "global", "presets", "controls", "signatures", "reporting", "connectors", "models", "aliases", "skills", "org_locks", "groups", "mcp_servers", "tools", "budgets", "routing"];
const CONTROL_KEYS = ["id", "type", "enabled", "description", "stages", "cost_tier", "fail_mode", "timeout_ms", "action", "mode", "presets", "locked", "taxonomy", "params"];

export const POLICY_SCHEMA = {
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: "https://acl.local/contracts/policy.schema.json",
  title: "PolicyDocument",
  description: "One Rogatka policy file (controls, models, groups, tools, budgets, routing).",
  type: "object",
  additionalProperties: false,
  properties: {
    $schema: { type: "string" },
    version: { type: "integer" },
    global: {
      type: "object",
      additionalProperties: false,
      properties: {
        mode: { enum: MODES, description: "enforce | monitor (monitor never blocks)" },
        default_preset: { enum: PRESETS },
        fail_mode: { type: "object" },
        latency_budget_ms: { type: "object" },
        store_redacted_payloads: { type: "boolean" },
      },
    },
    presets: {
      type: "object",
      propertyNames: { enum: PRESETS },
      additionalProperties: {
        type: "object",
        required: ["injection_threshold"],
        properties: {
          injection_threshold: { type: "number", minimum: 0, maximum: 1, description: "Block when the injection score is at least this value." },
          judge_band: { type: "array", minItems: 2, maxItems: 2, items: { type: "number" } },
          judge_on: { enum: ["none", "sinks", "outbound", "all"] },
          pii_action: { enum: ACTIONS },
          secret_action: { enum: ACTIONS },
          rule_of_two_action: { enum: ACTIONS },
          tool_mode: { enum: ["tiers", "allowlist"] },
        },
      },
    },
    controls: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "type", "stages", "cost_tier", "timeout_ms"],
        properties: {
          id: ID,
          type: { type: "string", pattern: "^[a-z][a-z0-9_]*$" },
          enabled: { type: "boolean", default: true },
          description: { type: "string" },
          stages: { type: "array", minItems: 1, items: { enum: POINTS } },
          cost_tier: { enum: COST_TIERS },
          fail_mode: { enum: ["closed", "open", "open_with_alert"] },
          timeout_ms: { type: "integer", minimum: 1, maximum: 60000 },
          action: { enum: ACTIONS, description: "Override the action the control emits on a hit." },
          mode: { enum: MODES, description: "Per-control shadow mode." },
          presets: { type: "array", items: { enum: PRESETS } },
          locked: { type: "boolean", description: "Org-locked: read-only in the panel." },
          taxonomy: { type: "object" },
          params: { type: "object" },
        },
      },
    },
    org_locks: {
      type: "array",
      items: { type: "object", required: ["id", "kind"], properties: { id: ID, kind: { enum: ["data_class_tier", "control_locked", "deny_resource"] } } },
    },
    signatures: { type: "object" },
    reporting: { type: "object" },
    connectors: { type: "object" },
    models: { type: "array" },
    aliases: { type: "object" },
    skills: { type: "object" },
    groups: { type: "object" },
    mcp_servers: { type: "object" },
    tools: { type: "object" },
    budgets: { type: "object" },
    routing: { type: "object" },
  },
};

// ---------------------------------------------------------------- validation (subset of the gateway's checks)

function lineOf(content: string, re: RegExp, from = 1): number | null {
  const lines = content.split("\n");
  for (let i = Math.max(0, from - 1); i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return null;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function controlsById(doc: YamlMap): Map<string, YamlMap> {
  const out = new Map<string, YamlMap>();
  for (const c of asList(doc.controls)) if (isMap(c) && asStr(c.id)) out.set(asStr(c.id)!, c);
  return out;
}

function withoutDescription(v: YamlMap | undefined): string {
  if (!v) return "";
  const { description: _d, ...rest } = v;
  return JSON.stringify(rest);
}

function validateOne(name: string, content: string, live: string | undefined): PolicyError[] {
  const parsed = tryParseYamlMap(content);
  if (!parsed.ok) return [{ file: name, path: null, line: parsed.error.line, column: parsed.error.column, message: parsed.error.message }];
  const doc = parsed.value;
  const errors: PolicyError[] = [];
  const err = (path: string, message: string, line: number | null) => errors.push({ file: name, path, line, column: null, message });

  for (const key of Object.keys(doc)) {
    if (!TOP_LEVEL.includes(key)) err(key, `unknown top-level key "${key}"`, lineOf(content, new RegExp(`^${esc(key)}\\s*:`)));
  }
  if (isMap(doc.global) && doc.global.mode !== undefined && !MODES.includes(String(doc.global.mode))) {
    err("global.mode", `mode must be one of ${MODES.join(", ")}`, lineOf(content, /^\s+mode\s*:/));
  }
  if (isMap(doc.presets)) {
    for (const [preset, p] of Object.entries(doc.presets)) {
      const at = lineOf(content, new RegExp(`^\\s+${esc(preset)}\\s*:`));
      if (!PRESETS.includes(preset)) err(`presets.${preset}`, `unknown preset "${preset}"`, at);
      if (!isMap(p)) continue;
      const t = p.injection_threshold;
      const tl = lineOf(content, /^\s+injection_threshold\s*:/, at ?? 1);
      if (typeof t !== "number") err(`presets.${preset}.injection_threshold`, "injection_threshold is required and must be a number", tl ?? at);
      else if (t < 0 || t > 1) err(`presets.${preset}.injection_threshold`, "injection_threshold must be between 0 and 1", tl);
    }
  }
  if (doc.controls !== undefined && !Array.isArray(doc.controls)) err("controls", "controls must be a list", lineOf(content, /^controls\s*:/));
  asList(doc.controls).forEach((c, i) => {
    if (!isMap(c)) return err(`controls[${i}]`, "each control must be a mapping", null);
    const id = asStr(c.id) ?? `#${i}`;
    const at = asStr(c.id) ? lineOf(content, new RegExp(`id\\s*:\\s*${esc(id)}\\b`)) : null;
    const field = (k: string) => lineOf(content, new RegExp(`^\\s+${esc(k)}\\s*:`), at ?? 1) ?? at;
    if (!asStr(c.id)) err(`controls[${i}].id`, "id is required", at);
    else if (!/^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$/.test(id)) err(`controls.${id}.id`, `"${id}" is not a valid rule id (e.g. SEC-PII-01)`, at);
    for (const k of Object.keys(c)) if (!CONTROL_KEYS.includes(k)) err(`controls.${id}.${k}`, `unknown field "${k}"`, field(k));
    if (!asStr(c.type)) err(`controls.${id}.type`, "type is required", at);
    const stages = asList(c.stages);
    if (stages.length === 0) err(`controls.${id}.stages`, "stages must list at least one inspection point", field("stages"));
    for (const s of stages) if (!POINTS.includes(String(s))) err(`controls.${id}.stages`, `unknown inspection point "${String(s)}"`, field("stages"));
    if (!COST_TIERS.includes(String(c.cost_tier))) err(`controls.${id}.cost_tier`, `cost_tier must be one of ${COST_TIERS.join(", ")}`, field("cost_tier"));
    const t = c.timeout_ms;
    if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 60000) err(`controls.${id}.timeout_ms`, "timeout_ms must be a whole number from 1 to 60000", field("timeout_ms"));
    if (c.action !== undefined && c.action !== null && !ACTIONS.includes(String(c.action))) err(`controls.${id}.action`, `"${String(c.action)}" is not a decision`, field("action"));
    if (c.mode !== undefined && c.mode !== null && !MODES.includes(String(c.mode))) err(`controls.${id}.mode`, `mode must be one of ${MODES.join(", ")}`, field("mode"));
  });

  // Org locks: locked controls and org_locks are read-only in the panel.
  if (errors.length === 0 && live !== undefined) {
    const before = tryParseYamlMap(live);
    if (before.ok) {
      const old = controlsById(before.value);
      const cur = controlsById(doc);
      for (const [id, c] of old) {
        if (c.locked !== true && !(policyStatus.locked_controls ?? []).includes(id)) continue;
        if (withoutDescription(c) !== withoutDescription(cur.get(id))) {
          err(`controls.${id}`, `locked control ${id} cannot be changed from the panel`, lineOf(content, new RegExp(`id\\s*:\\s*${esc(id)}\\b`)));
        }
      }
      const locks = (d: YamlMap) => JSON.stringify(d.org_locks ?? null);
      if (locks(before.value) !== locks(doc)) err("org_locks", "org locks cannot be removed or changed from the panel", lineOf(content, /^org_locks\s*:/));
    }
  }
  return errors;
}

function validateFiles(files: Record<string, string>): PolicyError[] {
  const live = currentFiles();
  return Object.entries(files).flatMap(([name, content]) =>
    name in live ? validateOne(name, content, live[name]) : [{ file: name, path: null, line: null, column: null, message: "unknown policy file" }],
  );
}

const nextVersionLabel = () => `v${Math.max(0, ...policyDb.versions.map((v) => v.id)) + 1}`;

// ---------------------------------------------------------------- dry-run (deterministic demo numbers)

/**
 * Injection threshold → [block->allow | allow->block (negative), attacks through %, false alarms %, tests passed of 144].
 * From PolicyEditor.dc.html (live 0.80: 2.1 % / 3.1 %, 144 / 144).
 */
const THRESHOLD_IMPACT: Record<string, [number, number, number, number]> = {
  "0.70": [-14, 1.1, 6.2, 144],
  "0.75": [-6, 1.6, 4.4, 144],
  "0.80": [0, 2.1, 3.1, 144],
  "0.85": [3, 3.5, 1.4, 142],
  "0.90": [5, 5.0, 1.0, 140],
};

function impactFor(t: number): [number, number, number, number] {
  const known = THRESHOLD_IMPACT[t.toFixed(2)];
  if (known) return known;
  const d = t - 0.8;
  return d > 0
    ? [Math.round(d * 60), +(2.1 + d * 30).toFixed(1), Math.max(0.2, +(3.1 - d * 20).toFixed(1)), Math.max(120, 144 - Math.round(d * 40))]
    : [Math.round(d * 140), Math.max(0.3, +(2.1 + d * 10).toFixed(1)), +(3.1 - d * 30).toFixed(1), 144];
}

const SUBJECTS = ["j.kowalski", "p.zielinski", "j.kowalski", "a.nowak", "m.lis", "t.wisniewski", "e.grabowska"];

function readPolicy(files: Record<string, string>) {
  const parsed = tryParseYamlMap(files["controls.yaml"] ?? "");
  if (!parsed.ok) return null;
  const doc = parsed.value;
  const presets = isMap(doc.presets) ? doc.presets : {};
  const preset = (isMap(doc.global) && asStr(doc.global.default_preset)) || "balanced";
  const p = presets[preset];
  const threshold = isMap(p) && typeof p.injection_threshold === "number" ? p.injection_threshold : 0.8;
  const session = controlsById(doc).get("SEC-SESSION-01");
  const level = (isMap(session?.params) && asStr((session!.params as YamlMap).threshold)) || "confidential";
  return { threshold, level };
}

function dryRun(body: S["DryRunRequest"]): S["DryRunResponse"] {
  const candidate = { ...currentFiles(), ...body.files };
  const errors = validateFiles(body.files);
  const evaluated = Math.min(body.last_n ?? 500, 500);
  const candidateVersion = nextVersionLabel();
  if (errors.length) return { candidate_version: candidateVersion, evaluated: 0, changed: 0, transitions: {}, samples: [], errors };
  const live = readPolicy(currentFiles());
  const next = readPolicy(candidate);
  const transitions: Record<string, number> = {};
  const samples: S["DryRunChange"][] = [];
  const addSamples = (n: number, before: S["Action"], after: S["Action"], ruleId: string) => {
    for (let i = 0; i < Math.min(n, 5); i++) {
      samples.push({
        event_id: `tr_${(0x5a10 + i * 37 + n).toString(16)}${ruleId === "SEC-PI-01" ? "c1" : "d2"}`,
        timestamp: new Date(Date.now() - (i + 1) * 47 * 60_000).toISOString(),
        subject: SUBJECTS[i % SUBJECTS.length],
        before_action: before,
        after_action: after,
        before_rule_ids: before === "allow" ? [] : [ruleId],
        after_rule_ids: after === "allow" ? [] : [ruleId],
      });
    }
  };
  // Suite numbers are demo-only extras carried in `transitions` under `suite:*` keys (the contract has no field for them).
  const [, asrLive, fprLive, testsLive] = impactFor(live?.threshold ?? 0.8);
  let suite = { asr: asrLive, fpr: fprLive, tests: testsLive };
  if (live && next && next.threshold !== live.threshold) {
    const [delta, asr, fpr, tests] = impactFor(next.threshold);
    const [liveDelta] = impactFor(live.threshold);
    const change = delta - liveDelta;
    if (change > 0) {
      transitions["block->allow"] = change;
      addSamples(change, "block", "allow", "SEC-PI-01");
    } else if (change < 0) {
      transitions["allow->block"] = -change;
      addSamples(-change, "allow", "block", "SEC-PI-01");
    }
    suite = { asr, fpr, tests };
  }
  if (live && next && next.level !== live.level) {
    const n = 9;
    if (next.level === "restricted") {
      transitions["route_local->allow"] = n;
      addSamples(n, "route_local", "allow", "SEC-SESSION-01");
    } else {
      transitions["allow->route_local"] = n;
      addSamples(n, "allow", "route_local", "SEC-SESSION-01");
    }
  }
  const changed = Object.values(transitions).reduce((a, b) => a + b, 0);
  Object.assign(transitions, {
    "suite:asr_before": asrLive,
    "suite:asr_after": suite.asr,
    "suite:fpr_before": fprLive,
    "suite:fpr_after": suite.fpr,
    "suite:tests_total": 144,
    "suite:tests_passed": suite.tests,
  });
  return { candidate_version: candidateVersion, evaluated, changed, transitions, samples, errors: [] };
}

// ---------------------------------------------------------------- handlers

const fileInfo = (name: string) => policyDb.files.find((f) => f.name === name);

const toVersion = ({ id, version, created_at, author, source, message, reason, files_changed }: (typeof policyDb.versions)[number]): S["PolicyVersion"] => ({
  id,
  version,
  created_at,
  author,
  source,
  message,
  reason,
  files_changed,
});

export const policyHandlers: HttpHandler[] = [
  http.get(adminPath("/policy"), () => HttpResponse.json(policyStatus)),

  http.get(adminPath("/policy/schema"), () => HttpResponse.json(POLICY_SCHEMA)),

  http.get(adminPath("/policy/files"), () => HttpResponse.json(policyStatus.files)),

  http.get(adminPath("/policy/files/:name"), ({ params }) => {
    const f = fileInfo(String(params.name));
    if (!f) return errorResponse(404, "not_found", "policy file not found");
    return HttpResponse.json({ name: f.name, version: f.version, size: f.content.length, modified_at: f.modified_at, content: f.content } satisfies S["PolicyFileContent"]);
  }),

  http.put(adminPath("/policy/files/:name"), async ({ params, request }) => {
    const name = String(params.name);
    if (!/^[a-z0-9_-]+\.yaml$/.test(name)) return errorResponse(422, "invalid_file_name", "policy file names must match ^[a-z0-9_-]+\\.yaml$");
    const f = fileInfo(name);
    if (!f) return errorResponse(404, "not_found", "policy file not found");
    const body = (await request.json()) as S["PolicyFileWrite"];
    if (body.base_version !== f.version) {
      return errorResponse(409, "stale_version", `${name} changed since version ${body.base_version.slice(0, 12)} was read; reload and re-apply your edit`, {
        file: name,
        current_version: f.version,
      });
    }
    const errors = validateFiles({ [name]: body.content });
    if (errors.length) {
      const locked = errors.some((e) => /locked|org lock/.test(e.message));
      return errorResponse(422, locked ? "locked_control" : "validation_failed", locked ? errors.map((e) => e.message).join(" | ") : `policy is invalid (${errors.length} error${errors.length === 1 ? "" : "s"})`, {
        errors,
      });
    }
    if (body.content !== f.content) commitPolicyVersion({ ...currentFiles(), [name]: body.content }, "panel", MOCK_USER, body.message ?? "");
    return HttpResponse.json(policyStatus);
  }),

  http.post(adminPath("/policy/validate"), async ({ request }) => {
    const body = (await request.json()) as S["ValidateRequest"];
    const errors = validateFiles(body.files);
    return HttpResponse.json({ valid: errors.length === 0, errors, candidate_version: errors.length ? null : nextVersionLabel() } satisfies S["ValidateResponse"]);
  }),

  http.post(adminPath("/policy/dry-run"), async ({ request }) => HttpResponse.json(dryRun((await request.json()) as S["DryRunRequest"]))),

  http.get(adminPath("/policy/versions"), ({ request }) => {
    const limit = intParam(queryOf(request), "limit", 50, 500);
    return HttpResponse.json([...policyDb.versions].sort((a, b) => b.id - a.id).slice(0, limit).map(toVersion));
  }),

  http.get(adminPath("/policy/versions/:id"), ({ params }) => {
    const v = policyDb.versions.find((x) => x.id === Number(params.id));
    return v ? HttpResponse.json(v) : errorResponse(404, "not_found", "policy version not found");
  }),

  http.post(adminPath("/policy/versions/:id/rollback"), async ({ params, request }) => {
    const v = policyDb.versions.find((x) => x.id === Number(params.id));
    if (!v) return errorResponse(404, "not_found", "policy version not found");
    // The body is optional; when given, `reason` is 3 to 500 characters after trimming (like the gateway).
    const text = await request.text();
    const body = text ? (JSON.parse(text) as Partial<components["schemas"]["PolicyRollbackRequest"]> | null) : null;
    const reason = body?.reason?.trim() ?? null;
    if (body && (reason === null || reason.length < 3 || reason.length > 500)) {
      return errorResponse(422, "validation_error", "reason must be 3 to 500 characters");
    }
    const target = v.files;
    const live = currentFiles();
    if (Object.keys(target).every((n) => target[n] === live[n])) {
      return errorResponse(409, "no_change", `${v.version} has the same content as the live version`);
    }
    const note = `rollback to version #${v.id} (${v.version})`;
    commitPolicyVersion({ ...live, ...target }, "rollback", MOCK_USER, reason ? `${note}: ${reason}` : note, reason);
    return HttpResponse.json(policyStatus);
  }),
];
