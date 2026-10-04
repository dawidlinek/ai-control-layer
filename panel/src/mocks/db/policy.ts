/**
 * Mock data: policy (status, files, versions). Demo story (HANDOFF section 6): live v8 was loaded from an
 * external edit of controls.yaml at 14:02; publishing the injection threshold from the panel makes v9.
 * The files are abridged copies of `policy/*.yaml` (no canary values, no secrets). Each version keeps a full
 * snapshot of the files so the diff, rollback and conflict flows work for real.
 */
import { demoClock } from "../time";
import { registerReset } from "./registry";
import type { PolicyStatus, PolicyVersionDetail } from "./types";

// ---------------------------------------------------------------- file builders

interface Knobs {
  /** presets.balanced.injection_threshold */
  threshold: string;
  /** SEC-EXFIL-01 params.scan_tool_results (the v8 external edit). */
  scanToolResults: boolean;
  /** SEC-MCP-01 params.on_drift */
  onDrift: "monitor" | "quarantine";
  /** groups.credit-analysts.preset */
  creditPreset: "balanced" | "strict";
  /** operations get `smart` */
  opsSmart: boolean;
  /** routing.complexity_bands.local_max */
  localMax: string;
}

function controlsYaml(k: Knobs): string {
  return `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# Controls, presets and global settings (concept §6, §11).
# Edit freely: the gateway validates, compiles and hot-swaps this file; an invalid edit keeps
# the last good version. Every control declares id, stages, cost_tier, fail_mode, timeout_ms.

global:
  mode: enforce                  # enforce | monitor
  default_preset: balanced       # monitor | balanced | strict | paranoid
  fail_mode: {deterministic: closed, semantic: open_with_alert}
  latency_budget_ms: {semantic: 150, total: 400}

presets:
  balanced:
    injection_threshold: ${k.threshold}
    judge_band: [0.3, 0.8]
    judge_on: sinks
    pii_action: pseudonymise
    secret_action: block
    rule_of_two_action: require_approval
  strict:
    injection_threshold: 0.50
    judge_band: [0.2, 0.9]
    judge_on: outbound
    pii_action: pseudonymise
    secret_action: block
    tool_mode: allowlist
    rule_of_two_action: block

controls:
  # ---- deterministic -------------------------------------------------------------------
  - id: SEC-PII-01
    type: pii
    enabled: true
    description: PII tier T0 – regex + validators (PESEL, NIP, REGON, IBAN mod-97, Luhn, email, phone)
    stages: [ingress, egress, tool_call, tool_result, embeddings]
    cost_tier: deterministic
    timeout_ms: 20
    params:
      entities: [PESEL, NIP, REGON, PL_ID_CARD, IBAN, CREDIT_CARD, EMAIL, PHONE]

  - id: SEC-SECRET-01
    type: secrets
    enabled: true
    locked: true                 # LOCK-02: secrets never leave
    description: Secrets and credentials (gitleaks-style rules, key prefixes, entropy) never leave
    stages: [ingress, egress, tool_call, tool_result, embeddings]
    cost_tier: deterministic
    timeout_ms: 20
    action: block

  - id: SEC-PI-01
    type: injection_classifier
    enabled: true
    description: Small injection/jailbreak classifier (ONNX) on prompts and tool results
    stages: [ingress, tool_result]
    cost_tier: l1
    timeout_ms: 80
    action: block

  - id: SEC-SAFE-01
    type: content_safety
    enabled: true
    mode: monitor                # logs only for now
    description: Content-safety judge on answers (local Qwen with a judge prompt)
    stages: [egress]
    cost_tier: l2
    timeout_ms: 1500

  - id: SEC-EXFIL-01
    type: url_egress
    enabled: true
    description: Markdown-image / link exfiltration, high-entropy query strings, domain allowlist
    stages: [egress, tool_call]
    cost_tier: deterministic
    timeout_ms: 10
    params:
      allow_domains: ["*.corp.example", "localhost"]
      strip_markdown_images: true
${k.scanToolResults ? "      scan_tool_results: true\n" : ""}      max_query_entropy: 3.5

  - id: SEC-FLOW-01
    type: rule_of_two
    enabled: true
    description: Rule of Two / lethal trifecta (untrusted input + sensitive data + external egress)
    stages: [tool_call]
    cost_tier: deterministic
    timeout_ms: 30

  - id: SEC-SESSION-01
    type: session_label
    enabled: true
    description: Once a session's high-water mark reaches the threshold, every later request in it is served by local models only
    stages: [ingress, embeddings]
    cost_tier: deterministic
    timeout_ms: 10
    params:
      threshold: confidential        # confidential | restricted

  - id: SEC-MCP-01
    type: mcp_pinning
    enabled: true
    description: tools/list hash pinning, description scan, name collisions; drift → quarantine
    stages: [mcp_tools_list]
    cost_tier: deterministic
    timeout_ms: 20
    params:
      on_drift: ${k.onDrift}        # quarantine | monitor

  - id: SEC-MODEL-01
    type: model_access
    enabled: true
    description: Model allowlist + data-class ceiling per model (forbidden → block, sensitive → route_local)
    stages: [ingress, embeddings]
    cost_tier: deterministic
    timeout_ms: 250

  - id: SEC-TOOL-01
    type: tool_policy
    enabled: true
    description: Tool tiers (deny/must/allow/confirm), pinned argument schemas, path/command/url/recipient checkers
    stages: [tool_call]
    cost_tier: deterministic
    timeout_ms: 250

  - id: SEC-SIG-01
    type: signatures
    enabled: true
    description: Signature feed matching (regex, url paths, package versions, IOC domains, hashes)
    stages: [ingress, tool_call, tool_result, mcp_initialize, mcp_tools_list, artifact_load]
    cost_tier: deterministic
    timeout_ms: 20

  - id: SEC-BUDGET-01
    type: budget
    enabled: true
    description: Hierarchical budgets, rate limits, circuit breaker, guard spend
    stages: [ingress, embeddings, tool_call]
    cost_tier: deterministic
    timeout_ms: 15

signatures:
  feed:
    url: http://feed-server:8080/bundle.json
    poll_s: 30
    verify: sha256
    on_fail: keep_last_good

reporting:
  audit_log:
    path: logs/audit.jsonl
    format: jsonl
    hash_chain: true
    store_raw_payloads: false
`;
}

function groupsYaml(k: Knobs): string {
  return `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# Org locks (ceilings no grant can exceed) and group-level permissions (concept §7.1, §11).
# Org locks are read-only in the panel: change them here, with a review.

org_locks:
  - id: LOCK-01
    kind: data_class_tier
    description: Confidential and restricted data never go to a cloud connector
    data_classes: [confidential, restricted]
    allowed_tiers: [local]
  - id: LOCK-02
    kind: control_locked
    description: Secrets never leave; the secrets control cannot be disabled from the panel
    controls: [SEC-SECRET-01]

groups:
  developers:
    description: Developers (OpenCode). No cloud model by default; a personal grant adds one.
    preset: balanced
    models: [auto, local]
    mcp_servers: [governed-tools, files, web, mail, rugpull-demo]

  credit-analysts:
    description: Bank credit analysts (LibreChat + OpenCode)
    preset: ${k.creditPreset}
    models: [auto, local, local/loan-memo]
    mcp_servers: [core-banking]
    max_external_data_class: internal

  operations:
    description: Operations (LibreChat)
    preset: balanced
    models: [${k.opsSmart ? "auto, local, smart" : "auto, local"}]

  security:
    description: Security team (panel analysts)
    preset: strict
    models: [auto, local]
`;
}

const MODELS_YAML = `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# Connectors and model registry (concept §7). Upstream model names come from the environment.

connectors:
  local:
    type: openai_compatible
    base_url: env:LOCAL_LLM_BASE_URL
    tier: local
  gemini:
    type: openai_compatible
    base_url: https://generativelanguage.googleapis.com/v1beta/openai/
    api_key: env:GEMINI_API_KEY        # never leaves the gateway
    tier: cloud

models:
  - id: local/qwen3.8-27b
    connector: local
    upstream_model: env:LOCAL_GENERAL_MODEL
    aliases: [local, fast]
    data_classes: [public, internal, confidential, restricted]
  - id: local/loan-memo
    connector: local
    upstream_model: env:LOCAL_GENERAL_MODEL
    data_classes: [public, internal, confidential]
  - id: gemini/flash
    connector: gemini
    upstream_model: env:GEMINI_MODEL
    aliases: [smart]
    data_classes: [public, internal]   # confidential/restricted never go to the cloud (LOCK-01)
  - id: gemini/pro
    connector: gemini
    upstream_model: env:GEMINI_PRO_MODEL
    aliases: [smart-pro]
    data_classes: [public, internal]
`;

const TOOLS_YAML = `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# MCP server allowlist and tool catalogue with IFC labels and tiers (concept §9).

mcp_servers:
  governed-tools:
    transport: streamable_http
    url: http://mcp-governed:8000/mcp
  core-banking:
    transport: streamable_http
    url: http://mcp-core-banking:8000/mcp

tools:
  opencode.read:
    labels: [reads_untrusted, touches_sensitive]
    default_tier: allow
  opencode.bash:
    capabilities: [exec, filesystem, network]
    default_tier: allow
  mail.send:
    labels: [external_egress]
    default_tier: confirm
`;

const BUDGETS_YAML = `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# Budgets and resource governance (concept §8). Hierarchy: org → group → user → agent → session.

budgets:
  org: {usd_month: 100, gpu_seconds_day: 3600}
  groups:
    developers: {tokens_day: 2000000, usd_day: 5}
    credit-analysts: {tokens_day: 1000000, usd_day: 2}
    operations: {tokens_day: 1000000, usd_day: 1}
    security: {tokens_day: 500000, usd_day: 1}
  agents:
    research-bot: {tokens_session: 50000, tool_calls_session: 40}
`;

function routingYaml(k: Knobs): string {
  return `# yaml-language-server: $schema=../contracts/policy.schema.json
#
# Router: sensitivity × complexity × budget (concept §7).

routing:
  sensitivity: {high: local_only, medium: redact_then_external, low: by_complexity}
  complexity_bands: {local_max: ${k.localMax}, ext_small_max: 0.6}
  targets:
    local: local/qwen3.8-27b
    ext_small: gemini/flash
    ext_large: gemini/pro
    degraded: local/qwen3.8-27b
  on_budget_exhausted: degrade_to_local
`;
}

export const POLICY_FILE_NAMES = ["controls.yaml", "models.yaml", "groups.yaml", "tools.yaml", "budgets.yaml", "routing.yaml"];

function filesFor(k: Knobs): Record<string, string> {
  return {
    "controls.yaml": controlsYaml(k),
    "models.yaml": MODELS_YAML,
    "groups.yaml": groupsYaml(k),
    "tools.yaml": TOOLS_YAML,
    "budgets.yaml": BUDGETS_YAML,
    "routing.yaml": routingYaml(k),
  };
}

// ---------------------------------------------------------------- helpers

/** Short content hash (FNV-1a), used as the file `version` for optimistic locking. */
export function contentHash(text: string): string {
  let h = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ text.charCodeAt(i), 0x5bd1e995) >>> 0;
  }
  return (h.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).slice(0, 12);
}

/** Unified diff between two texts (LCS on lines, 2 lines of context). */
export function unifiedDiff(name: string, before: string, after: string): string {
  if (before === after) return "";
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  type Op = { t: " " | "-" | "+"; s: string; ai: number; bi: number };
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) ops.push({ t: " ", s: a[i], ai: i++, bi: j++ });
    else if (j < m && (i === n || lcs[i][j + 1] >= lcs[i + 1][j])) ops.push({ t: "+", s: b[j], ai: i, bi: j++ });
    else ops.push({ t: "-", s: a[i], ai: i++, bi: j });
  }
  const CONTEXT = 2;
  const out = [`--- a/${name}`, `+++ b/${name}`];
  let k = 0;
  while (k < ops.length) {
    if (ops[k].t === " ") {
      k++;
      continue;
    }
    const start = Math.max(0, k - CONTEXT);
    let end = k;
    // Extend the hunk while changes are within 2 * CONTEXT lines of each other.
    for (;;) {
      while (end < ops.length && ops[end].t !== " ") end++;
      let next = end;
      while (next < ops.length && ops[next].t === " " && next - end < CONTEXT * 2) next++;
      if (next < ops.length && ops[next].t !== " ") end = next;
      else break;
    }
    const stop = Math.min(ops.length, end + CONTEXT);
    const hunk = ops.slice(start, stop);
    const aLen = hunk.filter((o) => o.t !== "+").length;
    const bLen = hunk.filter((o) => o.t !== "-").length;
    out.push(`@@ -${hunk[0].ai + 1},${aLen} +${hunk[0].bi + 1},${bLen} @@`);
    for (const o of hunk) out.push(`${o.t}${o.s}`);
    k = stop;
  }
  return out.join("\n");
}

export function diffFiles(before: Record<string, string>, after: Record<string, string>): { diff: string; changed: string[] } {
  const names = [...new Set([...Object.keys(before), ...Object.keys(after)])];
  const changed = names.filter((nme) => before[nme] !== after[nme]);
  return { diff: changed.map((nme) => unifiedDiff(nme, before[nme] ?? "", after[nme] ?? "")).join("\n"), changed };
}

const DAY = 86_400_000;
const daysBefore = (days: number, clock: string) => new Date(new Date(demoClock(clock)).getTime() - days * DAY).toISOString();

// ---------------------------------------------------------------- seed

const BASE: Knobs = { threshold: "0.75", scanToolResults: false, onDrift: "monitor", creditPreset: "balanced", opsSmart: false, localMax: "0.0" };

interface SeedVersion {
  at: string;
  author: string | null;
  source: PolicyVersionDetail["source"];
  message: string;
  knobs: Partial<Knobs>;
}

function seedVersions(): PolicyVersionDetail[] {
  const steps: SeedVersion[] = [
    { at: daysBefore(6, "08:30:00"), author: null, source: "startup", message: "First version, loaded when the gateway started", knobs: {} },
    { at: daysBefore(5, "10:12:00"), author: null, source: "file", message: "SEC-MCP-01 now quarantines MCP tools whose description changed", knobs: { onDrift: "quarantine" } },
    { at: daysBefore(4, "15:48:00"), author: "m.zielinska", source: "panel", message: "Operations can use the smart model", knobs: { opsSmart: true } },
    { at: daysBefore(3, "09:10:00"), author: "m.zielinska", source: "panel", message: "Send the simplest requests to the local model", knobs: { localMax: "0.2" } },
    { at: daysBefore(3, "09:40:00"), author: "k.wojcik", source: "rollback", message: "Rolled back to v3 after a bad routing change", knobs: { localMax: "0.0" } },
    { at: daysBefore(2, "11:05:00"), author: "m.zielinska", source: "panel", message: "credit-analysts moved to the strict preset", knobs: { creditPreset: "strict" } },
    { at: daysBefore(1, "16:20:00"), author: "m.zielinska", source: "panel", message: "Injection threshold 0.75 → 0.80 to cut false alarms", knobs: { threshold: "0.80" } },
    { at: demoClock("14:02:00"), author: null, source: "file", message: "SEC-EXFIL-01 now also strips links in tool results", knobs: { scanToolResults: true } },
  ];
  let knobs = { ...BASE };
  let prev: Record<string, string> = {};
  return steps.map((s, i) => {
    knobs = { ...knobs, ...s.knobs };
    const files = filesFor(knobs);
    const { diff, changed } = diffFiles(prev, files);
    prev = files;
    return {
      id: i + 1,
      version: `v${i + 1}`,
      created_at: s.at,
      author: s.author,
      source: s.source,
      message: s.message,
      files_changed: i === 0 ? Object.keys(files) : changed,
      diff: i === 0 ? "" : diff,
      files,
    };
  });
}

export interface MockPolicyFile {
  name: string;
  content: string;
  version: string;
  modified_at: string;
}

export interface PolicyDb {
  status: PolicyStatus;
  files: MockPolicyFile[];
  versions: PolicyVersionDetail[];
}

function seed(): PolicyDb {
  const versions = seedVersions();
  const live = versions[versions.length - 1];
  const files = POLICY_FILE_NAMES.map((name) => {
    // modified_at = the last version that changed this file.
    const last = [...versions].reverse().find((v) => v.files_changed.includes(name)) ?? versions[0];
    return { name, content: live.files[name], version: contentHash(live.files[name]), modified_at: last.created_at };
  });
  return {
    files,
    versions,
    status: {
      version: live.version,
      loaded_at: live.created_at,
      source: "file",
      files: [],
      last_error: [],
      locked_controls: ["LOCK-01", "LOCK-02", "SEC-SECRET-01"],
    },
  };
}

export const policyDb: PolicyDb = seed();

/** The status object (mutable on purpose: write handlers replace fields, e.g. `version` after a publish). */
export const policyStatus: PolicyStatus = policyDb.status;

/** Keep `status.files` in sync with the files. */
export function syncStatusFiles(): void {
  policyStatus.files = policyDb.files.map((f) => ({ name: f.name, version: f.version, size: f.content.length, modified_at: f.modified_at }));
}
syncStatusFiles();

/** The current content of every file, by name. */
export function currentFiles(): Record<string, string> {
  return Object.fromEntries(policyDb.files.map((f) => [f.name, f.content]));
}

/**
 * Commit a new policy version (panel write, rollback or an edit on disk): writes the files, snapshots a version
 * and updates the status. Returns the new version.
 */
export function commitPolicyVersion(next: Record<string, string>, source: PolicyVersionDetail["source"], author: string | null, message: string): PolicyVersionDetail {
  const before = currentFiles();
  const { diff, changed } = diffFiles(before, next);
  const at = new Date().toISOString();
  for (const f of policyDb.files) {
    if (next[f.name] !== undefined && next[f.name] !== f.content) {
      f.content = next[f.name];
      f.version = contentHash(f.content);
      f.modified_at = at;
    }
  }
  const id = Math.max(0, ...policyDb.versions.map((v) => v.id)) + 1;
  const version: PolicyVersionDetail = {
    id,
    version: `v${id}`,
    created_at: at,
    author,
    source,
    message,
    files_changed: changed,
    diff,
    files: currentFiles(),
  };
  policyDb.versions.push(version);
  Object.assign(policyStatus, { version: version.version, loaded_at: at, source, last_error: [] });
  syncStatusFiles();
  return version;
}

/**
 * Demo / test helper: someone edits a file on disk. With `invalid`, the edit is broken: the gateway keeps the last
 * good version and reports the error in `last_error` (the file on disk is not loaded).
 */
export function simulateDiskEdit(name: string, content: string, opts: { invalid?: { line: number; message: string } } = {}): void {
  if (opts.invalid) {
    policyStatus.last_error = [{ file: name, path: null, line: opts.invalid.line, column: null, message: opts.invalid.message }];
    return;
  }
  commitPolicyVersion({ ...currentFiles(), [name]: content }, "file", null, `${name} edited on disk`);
}

registerReset(() => {
  const fresh = seed();
  policyDb.files.splice(0, policyDb.files.length, ...fresh.files);
  policyDb.versions.splice(0, policyDb.versions.length, ...fresh.versions);
  Object.assign(policyStatus, fresh.status);
  syncStatusFiles();
});
