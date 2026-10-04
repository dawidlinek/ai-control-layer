/**
 * Rules shown on the Rules tab, derived from the policy files (`controls.yaml` controls + `groups.yaml` org locks).
 * The admin API has no "rules" endpoint: the files are the source of truth, so the panel reads them.
 * Plain-language copy comes from fixed templates per rule / control type (never from a model).
 */
import type { Decision } from "@/lib/decisions";
import { DECISIONS } from "@/lib/decisions";
import { asList, asStr, isMap, tryParseYamlMap, type YamlMap } from "./yaml-lite";

export type RuleMode = "enforce" | "monitor" | "always" | "off";
export type RuleSetting = "injection_threshold" | "session_threshold";

export interface PolicyRule {
  id: string;
  /** Control type (`pii`) or org-lock kind (`data_class_tier`). */
  type: string;
  /** Plain label of the type ("personal data"). */
  typeLabel: string;
  /** Short plain sentence for the table. */
  what: string;
  /** Plain explanation for the sidebar. */
  explain: string;
  action: Decision;
  mode: RuleMode;
  locked: boolean;
  /** Org lock that protects it (LOCK-02), or its own id for org locks. */
  lockId: string | null;
  file: string;
  /** 1-based line of the rule's `id:` in its file (null when not found). */
  line: number | null;
  /** The rule's lines in the file (for the "In the file" box). */
  snippet: { n: number; text: string }[];
  stages: string[];
  costTier: string | null;
  timeoutMs: number | null;
  setting: RuleSetting | null;
}

interface Copy {
  typeLabel?: string;
  what: string;
  explain: string;
}

/** Copy per rule id (prototype `RULES`), then per control type. */
const RULE_COPY: Record<string, Copy> = {
  "SEC-PII-01": {
    what: "Finds PESEL, IBAN, card numbers and names and swaps them for placeholders.",
    explain: "Personal data in a prompt, answer or tool result is replaced with placeholders before a model sees it, and put back only for the person who sent it.",
  },
  "SEC-SECRET-01": {
    what: "Stops API keys, passwords and tokens from leaving.",
    explain: "Secrets and credentials are never sent to a model or a tool. Protected by org lock LOCK-02.",
  },
  "SEC-PI-01": {
    what: "Blocks prompts and tool results that look like an injection.",
    explain: "A small local classifier scores every prompt and tool result for prompt injection. At or above the threshold the request is blocked.",
  },
  "SEC-SAFE-01": {
    what: "Checks answers for unsafe content; logs only for now.",
    explain: "A local judge reviews answers that look risky. It is in monitor mode, so it logs but never blocks.",
  },
  "SEC-EXFIL-01": {
    what: "Removes links and images that could carry data to unknown sites.",
    explain: "Markdown images and links to sites outside the company, or with data-like query strings, are removed from answers and tool results.",
  },
  "SEC-FLOW-01": {
    what: "Holds an action that mixes untrusted input, sensitive data and an outside target.",
    explain: "If one session has read untrusted content and sensitive data, any action that sends data outside needs a person to approve it, whatever the other checks say.",
  },
  "SEC-SESSION-01": {
    what: "Keeps a confidential conversation on local models for the rest of the session.",
    explain: "Each session remembers the most sensitive data it has seen. Once that reaches the threshold, every later request in the session is served by local models only, so the history never goes to a cloud model.",
  },
  "SEC-MCP-01": {
    what: "Quarantines MCP tools whose description changed after approval.",
    explain: "Each approved MCP tool is pinned. If its description or inputs change, it is hidden from agents and an incident is opened.",
  },
  "SEC-MODEL-01": {
    what: "Checks that the person may use the model and that the data may go to it.",
    explain: "Every request is checked against the person's allowed models and the data classes each model may receive. Sensitive data for a cloud model goes to a local one instead.",
  },
  "SEC-TOOL-01": {
    what: "Applies tool tiers and checks tool arguments (paths, commands, recipients).",
    explain: "Each tool call is checked against the tool's tier and its argument rules: workspace paths, safe commands, allowed recipients and URLs.",
  },
  "SEC-SIG-01": {
    what: "Matches known-bad packages, URLs and commands from the threat feed.",
    explain: "Requests, tool calls and tool results are matched against the signed threat feed (Known threats). A match is blocked.",
  },
  "SEC-BUDGET-01": {
    what: "Enforces spend and token budgets and the loop breaker.",
    explain: "Org, group, person and agent budgets are checked before each request. Over the limit, requests are blocked or moved to a local model.",
  },
  "LOCK-01": {
    what: "Cloud models never get confidential or restricted data.",
    explain: "Confidential and restricted data always go to a local model, whatever a group or personal grant says.",
  },
  "LOCK-02": {
    what: "Secrets never leave; the secrets rule cannot be turned off here.",
    explain: "The secrets rule (SEC-SECRET-01) cannot be disabled or changed from the panel.",
  },
};

const TYPE_LABEL: Record<string, string> = {
  pii: "personal data",
  pii_ner: "personal data (names)",
  secrets: "secrets",
  injection_classifier: "injection classifier",
  content_safety: "content-safety judge",
  url_egress: "links and images",
  rule_of_two: "Rule of Two",
  session_label: "session label",
  mcp_pinning: "MCP tool changes",
  mcp_protocol: "MCP protocol",
  model_access: "model access",
  tool_policy: "tool policy",
  signatures: "known threats",
  budget: "budgets",
  loop_detector: "loops",
  normalise: "normalise",
  taint_labels: "session labels from tools",
  data_class_tier: "org lock",
  control_locked: "org lock",
  deny_resource: "org lock",
};

/** Default action per control type when the YAML has no `action:` (preset fields where they exist). */
function defaultAction(type: string, preset: YamlMap): Decision {
  const fromPreset = (k: string, d: Decision): Decision => {
    const v = asStr(preset[k]);
    return v && (DECISIONS as readonly string[]).includes(v) ? (v as Decision) : d;
  };
  switch (type) {
    case "pii":
    case "pii_ner":
      return fromPreset("pii_action", "pseudonymise");
    case "secrets":
      return fromPreset("secret_action", "block");
    case "rule_of_two":
      return fromPreset("rule_of_two_action", "require_approval");
    case "session_label":
      return "route_local";
    case "content_safety":
    case "taint_labels":
    case "normalise":
      return "monitor";
    case "url_egress":
      return "block";
    default:
      return "block";
  }
}

function lineOf(content: string, re: RegExp, from = 1): number | null {
  const lines = content.split("\n");
  for (let i = Math.max(0, from - 1); i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return null;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Line of `id: <ID>` in a file (block or flow style). */
export function lineOfId(content: string, id: string): number | null {
  return lineOf(content, new RegExp(`(^|[\\s{,-])id\\s*:\\s*["']?${esc(id)}["']?\\s*(,|}|$|#)`));
}

/** The lines of the list item that starts at `line` (until the next item / dedent), comments and blank tail trimmed. */
export function itemBlock(content: string, line: number, max = 14): { n: number; text: string }[] {
  const lines = content.split("\n");
  const first = lines[line - 1] ?? "";
  const dash = first.indexOf("-");
  const itemIndent = dash >= 0 && first.slice(0, dash).trim() === "" ? dash : first.length - first.trimStart().length;
  const out: { n: number; text: string }[] = [{ n: line, text: first }];
  for (let i = line; i < lines.length && out.length < max; i++) {
    const l = lines[i];
    if (l.trim() === "") break;
    const ind = l.length - l.trimStart().length;
    if (ind <= itemIndent) break;
    out.push({ n: i + 1, text: l });
  }
  return out;
}

/** 1-based lines of org-locked content (locked controls in controls.yaml, `org_locks` items in groups.yaml). */
export function lockedLines(file: string, content: string, lockedIds: readonly string[]): number[] {
  const out = new Set<number>();
  const parsed = tryParseYamlMap(content);
  if (!parsed.ok) return [];
  const doc = parsed.value;
  if (file === "controls.yaml") {
    for (const c of asList(doc.controls)) {
      if (!isMap(c)) continue;
      const id = asStr(c.id);
      if (!id || !(c.locked === true || lockedIds.includes(id))) continue;
      const l = lineOfId(content, id);
      if (l) for (const b of itemBlock(content, l, 40)) out.add(b.n);
    }
  }
  const lockStart = lineOf(content, /^org_locks\s*:/);
  if (lockStart) {
    out.add(lockStart);
    const lines = content.split("\n");
    for (let i = lockStart; i < lines.length; i++) {
      const l = lines[i];
      if (l.trim() !== "" && !/^\s/.test(l)) break;
      if (l.trim() !== "") out.add(i + 1);
    }
  }
  return [...out].sort((a, b) => a - b);
}

export interface PolicyFiles {
  controls?: string;
  groups?: string;
}

/** Build the rule list from the files. Unparseable files contribute nothing (the YAML tab shows the error). */
export function deriveRules(files: PolicyFiles, lockedControls: readonly string[]): PolicyRule[] {
  const rules: PolicyRule[] = [];
  const lockOf = new Map<string, string>();
  const groups = files.groups ? tryParseYamlMap(files.groups) : null;
  const orgLocks = groups?.ok ? asList(groups.value.org_locks).filter(isMap) : [];
  for (const l of orgLocks) for (const c of asList(l.controls)) if (asStr(c) && asStr(l.id)) lockOf.set(asStr(c)!, asStr(l.id)!);

  const controls = files.controls ? tryParseYamlMap(files.controls) : null;
  if (controls?.ok && files.controls) {
    const doc = controls.value;
    const globalMode = (isMap(doc.global) && asStr(doc.global.mode)) || "enforce";
    const presetName = (isMap(doc.global) && asStr(doc.global.default_preset)) || "balanced";
    const preset = isMap(doc.presets) && isMap(doc.presets[presetName]) ? (doc.presets[presetName] as YamlMap) : {};
    for (const c of asList(doc.controls)) {
      if (!isMap(c) || !asStr(c.id)) continue;
      const id = asStr(c.id)!;
      const type = asStr(c.type) ?? "";
      const enabled = c.enabled !== false;
      const mode: RuleMode = !enabled ? "off" : (asStr(c.mode) ?? globalMode) === "monitor" ? "monitor" : "enforce";
      const declared = asStr(c.action);
      const action: Decision =
        mode === "monitor" ? "monitor" : declared && (DECISIONS as readonly string[]).includes(declared) ? (declared as Decision) : defaultAction(type, preset);
      const locked = c.locked === true || lockedControls.includes(id) || lockOf.has(id);
      const line = lineOfId(files.controls, id);
      const copy = RULE_COPY[id];
      rules.push({
        id,
        type,
        typeLabel: copy?.typeLabel ?? TYPE_LABEL[type] ?? type.replace(/_/g, " "),
        what: copy?.what ?? asStr(c.description) ?? "",
        explain: copy?.explain ?? asStr(c.description) ?? "",
        action,
        mode,
        locked,
        lockId: locked ? (lockOf.get(id) ?? null) : null,
        file: "controls.yaml",
        line,
        snippet: line ? itemBlock(files.controls, line) : [],
        stages: asList(c.stages).map(String),
        costTier: asStr(c.cost_tier) ?? null,
        timeoutMs: typeof c.timeout_ms === "number" ? c.timeout_ms : null,
        setting: locked ? null : type === "injection_classifier" ? "injection_threshold" : type === "session_label" ? "session_threshold" : null,
      });
    }
  }

  if (files.groups) {
    for (const l of orgLocks) {
      const id = asStr(l.id);
      if (!id) continue;
      const kind = asStr(l.kind) ?? "control_locked";
      const line = lineOfId(files.groups, id);
      const copy = RULE_COPY[id];
      const description = asStr(l.description) ?? "";
      rules.push({
        id,
        type: kind,
        typeLabel: "org lock",
        what: copy?.what ?? description,
        explain: copy?.explain ?? description,
        action: kind === "data_class_tier" ? "route_local" : "block",
        mode: "always",
        locked: true,
        lockId: id,
        file: "groups.yaml",
        line,
        snippet: line ? itemBlock(files.groups, line) : [],
        stages: [],
        costTier: null,
        timeoutMs: null,
        setting: null,
      });
    }
  }
  return rules;
}

// ---------------------------------------------------------------- settings: read and edit the YAML text

/** Live value of the injection threshold of the default preset (`presets.<default>.injection_threshold`). */
export function readInjectionThreshold(controls: string): { value: number; preset: string } | null {
  const parsed = tryParseYamlMap(controls);
  if (!parsed.ok) return null;
  const doc = parsed.value;
  const preset = (isMap(doc.global) && asStr(doc.global.default_preset)) || "balanced";
  const p = isMap(doc.presets) ? doc.presets[preset] : undefined;
  return isMap(p) && typeof p.injection_threshold === "number" ? { value: p.injection_threshold, preset } : null;
}

export type SessionLevel = "confidential" | "restricted";

export function readSessionThreshold(controls: string): SessionLevel | null {
  const parsed = tryParseYamlMap(controls);
  if (!parsed.ok) return null;
  for (const c of asList(parsed.value.controls)) {
    if (isMap(c) && asStr(c.type) === "session_label") {
      const t = isMap(c.params) ? asStr(c.params.threshold) : undefined;
      return t === "restricted" ? "restricted" : "confidential";
    }
  }
  return null;
}

/** Replace the value of `key:` in the block that starts at `startLine` (keeps indentation and trailing comment). */
function replaceInBlock(content: string, startLine: number, key: string, value: string): string | null {
  const lines = content.split("\n");
  const start = lines[startLine - 1] ?? "";
  const baseIndent = start.length - start.trimStart().length;
  for (let i = startLine; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === "" || l.trim().startsWith("#")) continue;
    const ind = l.length - l.trimStart().length;
    if (ind <= baseIndent) break;
    const m = new RegExp(`^(\\s+${esc(key)}\\s*:\\s*)([^\\s#]+)(.*)$`).exec(l);
    if (m) {
      lines[i] = `${m[1]}${value}${m[3]}`;
      return lines.join("\n");
    }
  }
  return null;
}

/** `controls.yaml` with `presets.<preset>.injection_threshold` set to `value` (two decimals). */
export function withInjectionThreshold(controls: string, preset: string, value: number): string | null {
  const presets = lineOf(controls, /^presets\s*:/);
  if (!presets) return null;
  const block = lineOf(controls, new RegExp(`^\\s+${esc(preset)}\\s*:\\s*(#.*)?$`), presets);
  return block ? replaceInBlock(controls, block, "injection_threshold", value.toFixed(2)) : null;
}

/** `controls.yaml` with SEC-SESSION-01's `params.threshold` set. */
export function withSessionThreshold(controls: string, ruleId: string, level: SessionLevel): string | null {
  const line = lineOfId(controls, ruleId);
  return line ? replaceInBlock(controls, line, "threshold", level) : null;
}
