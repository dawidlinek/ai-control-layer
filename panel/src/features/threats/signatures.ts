/**
 * Plain-language copy for the signatures of the active feed bundle (`GET /feed/signatures`): what each rule
 * "looks at", its tags and expiry, plus the choices of the Add rule form.
 */
import type { FeedSignature, FeedTarget } from "@/lib/api/types";
import { formatWhen } from "@/lib/format";

/** What a rule looks at (`FeedSignature.target`) in words an analyst uses. */
export const LOOKS_AT: Record<FeedTarget, string> = {
  package: "package",
  domain: "domain",
  url: "URL in a tool call",
  command: "shell command",
  tool_description: "tool description",
  prompt_text: "user input",
  answer_text: "answer text",
  any_text: "any text",
  tool_hash: "tool pin",
  manifest_hash: "manifest pin",
  yara: "model file (YARA)",
  opcode: "model file (opcode)",
};

export function looksAt(target: FeedTarget): string {
  return LOOKS_AT[target] ?? target;
}

/** ATLAS techniques, OWASP ids and CVEs of a rule, " · "-joined; "—" when it has none. */
export function tagsOf(s: Pick<FeedSignature, "atlas_technique" | "owasp" | "cve">): string {
  const tags = [...s.atlas_technique, ...s.owasp, ...s.cve];
  return tags.length ? tags.join(" · ") : "—";
}

export function expiresLabel(s: Pick<FeedSignature, "expires" | "expired">): string {
  if (!s.expires) return "never";
  return s.expired ? `expired ${formatWhen(s.expires)}` : formatWhen(s.expires);
}

/** The next free `FEED-LOCAL-000N` for the Add rule form. */
export function nextLocalId(existing: readonly string[]): string {
  let max = 0;
  for (const id of existing) {
    const m = /^FEED-LOCAL-(\d+)$/.exec(id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `FEED-LOCAL-${String(max + 1).padStart(4, "0")}`;
}

/** Targets the Add rule form offers (the contract's `FeedRuleCreate.target`), with the form's wording. */
export const RULE_TARGETS = [
  { value: "package", label: "Package (pip / npm install)" },
  { value: "command", label: "Shell command" },
  { value: "url", label: "URL in a tool call" },
  { value: "domain", label: "Domain" },
  { value: "tool_description", label: "Tool description (MCP)" },
  { value: "prompt_text", label: "User input" },
  { value: "answer_text", label: "Answer text" },
  { value: "any_text", label: "Any text" },
] as const satisfies readonly { value: Exclude<FeedTarget, "tool_hash" | "manifest_hash" | "yara" | "opcode">; label: string }[];

export type RuleTarget = (typeof RULE_TARGETS)[number]["value"];

export const RULE_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const RULE_ACTIONS = [
  { value: "block", label: "Block" },
  { value: "require_approval", label: "Ask for approval" },
  { value: "sanitize", label: "Sanitize" },
  { value: "redact", label: "Redact" },
  { value: "monitor", label: "Monitor only" },
] as const;
