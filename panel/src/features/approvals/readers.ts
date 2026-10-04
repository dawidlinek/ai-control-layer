/**
 * Typed, tolerant readers over the `Approval` contract. The contract has no structured fields for the approver
 * label, client, data class, red flags, preview or why-held sources (API gap, see ARCHITECTURE.md), so:
 *   - approver label comes from `approver_scope`,
 *   - details / client / data class / preview are read from `arguments_preview` (line 1 = the command,
 *     then `Key: value` lines, then a blank line, `--- <title>` and preview lines),
 *   - why-held sources are read from `reason` (line 1 = short reason, then `flag | text | time | trace` lines),
 *   - red flags are derived deterministically from the details (company domain, secret scan).
 * Every reader tolerates a plain one-line value (what a real gateway may send today).
 */
import type { Approval } from "@/lib/api/types";
import type { Decision } from "@/lib/decisions";

export const COMPANY_DOMAIN = "corp.example";
export const AUTO_DENY_MINUTES = 10;

export type ApproverLabel = "Security team" | "Team lead";

export function approverLabel(a: Pick<Approval, "approver_scope">): ApproverLabel {
  return a.approver_scope === "admin" ? "Security team" : "Team lead";
}

export interface Detail {
  key: string;
  value: string;
  /** Red-flag chip text, derived from the value. */
  flag?: string;
}

export type PreviewKind = "diff" | "email" | "plan" | "text";

export interface PreviewLine {
  /** `+` added, `-` removed, `~` changed, ` ` context. */
  sign: "+" | "-" | "~" | " ";
  text: string;
}

export interface Preview {
  kind: PreviewKind;
  title: string;
  lines: PreviewLine[];
}

export interface ParsedArguments {
  command: string;
  details: Detail[];
  client: string | null;
  device: string | null;
  dataClass: string | null;
  preview: Preview | null;
}

/** Keys that describe the context, not the action: shown in the facts / Who column, not in the details. */
const META_KEYS = new Set(["client", "device", "data class"]);

function flagFor(key: string, value: string): string | undefined {
  const k = key.toLowerCase();
  if (k === "remote") {
    const host = value.replace(/^[a-z]+:\/\//i, "").split(/[/:]/)[0]?.toLowerCase() ?? "";
    return host === COMPANY_DOMAIN || host.endsWith(`.${COMPANY_DOMAIN}`) ? undefined : "not a company remote";
  }
  if (k === "secret scan") {
    return /^(0\b|none|clean|no )/i.test(value.trim()) ? undefined : "secret found";
  }
  if (k === "to" || k === "cc" || k === "bcc" || k === "recipient" || k === "recipients") {
    const addresses = value.split(/[,;\s]+/).filter((v) => v.includes("@"));
    return addresses.some((v) => !v.toLowerCase().endsWith(`@${COMPANY_DOMAIN}`)) ? `outside @${COMPANY_DOMAIN}` : undefined;
  }
  return undefined;
}

function previewKind(a: Pick<Approval, "tool">, command: string): PreviewKind {
  const tool = (a.tool ?? "").toLowerCase();
  if (tool.startsWith("email") || tool.startsWith("mail")) return "email";
  if (/^terraform\b/.test(command)) return "plan";
  if (/^git\b/.test(command)) return "diff";
  return "text";
}

function toLine(raw: string): PreviewLine {
  const first = raw.charAt(0);
  if (first === "+" || first === "-" || first === "~" || first === " ") return { sign: first, text: raw.slice(1) };
  return { sign: " ", text: raw };
}

/** Parse `arguments_preview`. A one-line preview gives just the command. */
export function parseArguments(a: Pick<Approval, "arguments_preview" | "tool">): ParsedArguments {
  const all = (a.arguments_preview ?? "").replace(/\r\n/g, "\n").split("\n");
  const command = (all[0] ?? "").trim();
  const out: ParsedArguments = { command, details: [], client: null, device: null, dataClass: null, preview: null };
  let i = 1;
  for (; i < all.length; i++) {
    const line = all[i];
    if (line.trim() === "") break;
    const m = /^([^:]{1,40}):\s*(.*)$/.exec(line);
    if (!m) break;
    const key = m[1].trim();
    const value = m[2].trim();
    const lower = key.toLowerCase();
    if (META_KEYS.has(lower)) {
      if (lower === "client") out.client = value;
      else if (lower === "device") out.device = value;
      else out.dataClass = value;
      continue;
    }
    out.details.push({ key, value, flag: flagFor(key, value) });
  }
  while (i < all.length && all[i].trim() === "") i++;
  if (i < all.length) {
    let title = "Preview";
    if (all[i].startsWith("--- ")) {
      title = all[i].slice(4).trim();
      i++;
    }
    const lines = all.slice(i).filter((l, idx, arr) => !(idx === arr.length - 1 && l.trim() === "")).map(toLine);
    if (lines.length > 0) out.preview = { kind: previewKind(a, command), title, lines };
  }
  return out;
}

/** Short label of the action for the Request column: `git push`, `terraform apply`, `email.send`. */
export function shortAction(a: Pick<Approval, "tool">, command: string): string {
  const tool = a.tool ?? "";
  if (tool === "bash" || tool === "shell" || tool === "") {
    const words = command.split(/\s+/).filter(Boolean);
    return words.slice(0, 2).join(" ") || tool || "call";
  }
  return tool;
}

/** `$` for shell commands, `tool` for tool calls (the muted prompt before the command). */
export function promptOf(a: Pick<Approval, "tool">): string {
  return a.tool === "bash" || a.tool === "shell" ? "$" : "tool";
}

export type SourceFlag = "untrusted" | "sensitive" | "external" | "irreversible" | string;

export interface HeldSource {
  n: number;
  flag: SourceFlag;
  text: string;
  /** ISO time, or null for "now" (the held call itself). */
  at: string | null;
  traceId: string | null;
}

export interface ParsedReason {
  short: string;
  sources: HeldSource[];
}

/** Parse `reason`: first line short reason, then `flag | text | time | trace` lines. */
export function parseReason(a: Pick<Approval, "reason">): ParsedReason {
  const all = (a.reason ?? "").replace(/\r\n/g, "\n").split("\n");
  const short = (all[0] ?? "").trim();
  const sources: HeldSource[] = [];
  for (const line of all.slice(1)) {
    const parts = line.split("|").map((p) => p.trim());
    if (parts.length < 2 || !parts[0] || !parts[1]) continue;
    const at = parts[2] && parts[2] !== "now" && !Number.isNaN(Date.parse(parts[2])) ? parts[2] : null;
    sources.push({ n: sources.length + 1, flag: parts[0], text: parts[1], at, traceId: parts[3] || null });
  }
  return { short: short || "held for a person", sources };
}

/** Colour of a why-held source (the prototype uses the decision tint of what happened at that step). */
export function sourceDecision(flag: SourceFlag): Decision {
  switch (flag) {
    case "untrusted":
      return "downgrade";
    case "sensitive":
      return "redact";
    case "irreversible":
      return "block";
    default:
      return "require_approval";
  }
}

/** One line next to the rule chip. */
export function ruleSentence(ruleId: string | undefined, reason: ParsedReason): string {
  if (ruleId === "SEC-FLOW-01") {
    return reason.sources.length >= 3 ? "Rule of Two: this call would complete all three:" : "Rule of Two";
  }
  if (ruleId === "AUTHZ-TOOL-01") return `tool tier confirm · ${reason.short}`;
  return reason.short;
}

export function riskLabel(score: number): string {
  const level = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  return `${score.toFixed(2)} · ${level}`;
}

const SERVER_LABEL: Record<string, string> = { opencode: "OpenCode", librechat: "LibreChat" };

export function clientApp(a: Pick<Approval, "server">): string | null {
  if (!a.server) return null;
  return SERVER_LABEL[a.server] ?? null;
}

/** What the approval refers to in the result message: "git push to github.com/…", "this e-mail". */
export function targetOf(a: Pick<Approval, "tool" | "arguments_preview">, parsed: ParsedArguments): string {
  const short = shortAction(a, parsed.command);
  const detail = (k: string) => parsed.details.find((d) => d.key.toLowerCase() === k)?.value;
  if (parsed.preview?.kind === "email" || (a.tool ?? "").startsWith("email")) return "this e-mail";
  const remote = detail("remote");
  if (remote) return `${short} to ${remote}`;
  const ws = detail("workspace");
  if (ws) return `${short} in ${ws}`;
  return parsed.command || short;
}

export interface Person {
  name: string;
  isAgent: boolean;
}

/**
 * The plain first sentence of the sidebar, from a template filled with the record (never an LLM).
 */
export function approvalSentence(
  a: Approval,
  parsed: ParsedArguments,
  reason: ParsedReason,
  who: Person,
): string {
  if (a.status === "approved") {
    const by = a.decided_by ?? "an approver";
    if (a.elevation) {
      const mins = Math.max(1, Math.round((Date.parse(a.elevation.until) - Date.parse(a.decided_at ?? a.created_at)) / 60_000));
      return `Approved by ${by} with a ${mins}-minute elevation.`;
    }
    return `Approved once by ${by}.`;
  }
  if (a.status === "denied") return `Denied by ${a.decided_by ?? "an approver"}.`;
  if (a.status === "expired") return `Nobody answered in ${AUTO_DENY_MINUTES} minutes, so it was denied automatically.`;

  const actor = who.isAgent ? who.name : `${who.name}’s agent`;
  const to = parsed.details.find((d) => d.key.toLowerCase() === "to")?.value;
  const action =
    parsed.preview?.kind === "email" || (a.tool ?? "").startsWith("email")
      ? `send an e-mail${to ? ` to ${to}` : ""}`
      : `run ${targetOf(a, parsed)}`;
  const earlier = reason.sources.filter((s) => s.flag !== "external" && s.at);
  const parts = [`${actor} wants to ${action}.`];
  if (earlier.length > 0) parts.push(`Earlier in the same session it ${earlier.map((s) => s.text).join(" and ")}.`);
  const flags = parsed.details.filter((d) => d.flag).map((d) => d.flag);
  if (flags.length > 0) parts.push(`Flagged: ${flags.join(", ")}.`);
  parts.push("A person has to confirm it before it runs.");
  return parts.join(" ");
}
