/**
 * Readers over the `Approval` contract. The gateway sends typed `approver_label`, `data_class`, `client`, `flags`,
 * `preview` and `reasons`; the panel reads those first. What the contract still has no field for (the detail lines of
 * the call and the device) comes from `arguments_preview` (line 1 = the command, then optional `Key: value` lines),
 * and red flags are also derived from those details (company domain, secret scan). Every reader tolerates a plain
 * one-line `arguments_preview` / `reason`, and an older gateway without the typed fields.
 */
import type { Approval } from "@/lib/api/types";

export const COMPANY_DOMAIN = "corp.example";
export const AUTO_DENY_MINUTES = 10;

export function approverLabel(a: Pick<Approval, "approver_scope" | "approver_label">): string {
  return a.approver_label ?? (a.approver_scope === "admin" ? "Security team" : "Team lead");
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
  device: string | null;
}

/** Keys that describe the context, not the action: shown in the session fact, not in the details. */
const META_KEYS = new Set(["device"]);

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

function toLine(raw: string): PreviewLine {
  const first = raw.charAt(0);
  if (first === "+" || first === "-" || first === "~" || first === " ") return { sign: first, text: raw.slice(1) };
  return { sign: " ", text: raw };
}

/** Parse `arguments_preview`. A one-line preview gives just the command. */
export function parseArguments(a: Pick<Approval, "arguments_preview">): ParsedArguments {
  const all = (a.arguments_preview ?? "").replace(/\r?\n/g, "\n").split("\n");
  const command = (all[0] ?? "").trim();
  const out: ParsedArguments = { command, details: [], device: null };
  for (const line of all.slice(1)) {
    const m = /^([^:]{1,40}):\s*(.*)$/.exec(line);
    if (!m) break;
    const key = m[1].trim();
    const value = m[2].trim();
    if (META_KEYS.has(key.toLowerCase())) out.device = value;
    else out.details.push({ key, value, flag: flagFor(key, value) });
  }
  return out;
}

const PREVIEW_TITLE: Record<PreviewKind, string> = { diff: "Changes", email: "Message (personal data masked)", plan: "Plan", text: "Preview" };

/** The typed redacted preview as lines for the diff box. */
export function previewOf(a: Pick<Approval, "preview">): Preview | null {
  if (!a.preview?.body.trim()) return null;
  const lines = a.preview.body.replace(/\r?\n/g, "\n").split("\n").map(toLine);
  return { kind: a.preview.type, title: PREVIEW_TITLE[a.preview.type], lines };
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

/** Why it was held: one line per holding control; an older gateway's single-line `reason` as the fallback. */
export function reasonsOf(a: Pick<Approval, "reasons" | "reason">): string[] {
  if (a.reasons.length > 0) return a.reasons;
  const first = (a.reason ?? "").split("\n")[0].trim();
  return [first || "held for a person"];
}

/** Short name of the rule next to its chip. */
export function ruleTitle(ruleId: string | undefined): string | null {
  if (ruleId === "SEC-FLOW-01") return "Rule of Two";
  if (ruleId === "AUTHZ-TOOL-01") return "Tool tier: confirm";
  return null;
}

export function riskLabel(score: number): string {
  const level = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  return `${score.toFixed(2)} · ${level}`;
}

const CLIENT_LABEL: Record<string, string> = { opencode: "OpenCode", librechat: "LibreChat" };

export function clientApp(a: Pick<Approval, "client" | "server">): string | null {
  const c = a.client ?? a.server;
  return c ? (CLIENT_LABEL[c.toLowerCase()] ?? c) : null;
}

/** What the approval refers to in the result message: "git push to github.com/…", "this e-mail". */
export function targetOf(a: Pick<Approval, "tool" | "preview">, parsed: ParsedArguments): string {
  const short = shortAction(a, parsed.command);
  const detail = (k: string) => parsed.details.find((d) => d.key.toLowerCase() === k)?.value;
  if (a.preview?.type === "email" || (a.tool ?? "").startsWith("email")) return "this e-mail";
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
export function approvalSentence(a: Approval, parsed: ParsedArguments, reasons: string[], who: Person): string {
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
    a.preview?.type === "email" || (a.tool ?? "").startsWith("email")
      ? `send an e-mail${to ? ` to ${to}` : ""}`
      : `run ${targetOf(a, parsed)}`;
  const parts = [`${actor} wants to ${action}.`, `Held: ${reasons[0].replace(/[.:]+$/, "")}.`];
  const flags = [...a.flags, ...parsed.details.flatMap((d) => (d.flag ? [d.flag] : []))];
  if (flags.length > 0) parts.push(`Flagged: ${[...new Set(flags)].join(", ")}.`);
  parts.push("A person has to confirm it before it runs.");
  return parts.join(" ");
}
