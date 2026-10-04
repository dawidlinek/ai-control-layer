/** Small readers and sentence templates for the Policies screen. */
import { ApiError } from "@/lib/api/client";
import type { DryRunResponse, PolicyStatus, PolicyVersion } from "@/lib/api/types";
import { formatClock, formatNumber, formatWhen } from "@/lib/format";
import type { Decision } from "@/lib/decisions";

/**
 * Display label of a policy version: `v8`. The gateway's version string is a content hash; the history list
 * gives it a sequence id, which is what people say ("v8").
 */
export function versionLabel(version: string, versions?: readonly PolicyVersion[]): string {
  if (/^v\d+$/.test(version)) return version;
  const v = versions?.find((x) => x.version === version);
  return v ? `v${v.id}` : version.slice(0, 8);
}

export const labelOf = (v: PolicyVersion) => (/^v\d+$/.test(v.version) ? v.version : `v${v.id}`);

/** The label the next published version will get ("v9"). */
export function nextVersionLabel(versions: readonly PolicyVersion[] | undefined): string | null {
  if (!versions || versions.length === 0) return null;
  return `v${Math.max(...versions.map((v) => v.id)) + 1}`;
}

/** "loaded 14:02 from the file (edited on disk)" and friends. */
export function liveSentence(status: PolicyStatus, versions: readonly PolicyVersion[] | undefined, me: string, now = Date.now()): string {
  const at = new Date(status.loaded_at).getTime();
  const when = now - at < 60_000 ? "just now" : `at ${formatClock(at)}`;
  const entry = versions?.find((v) => v.version === status.version);
  const who = entry?.author ? (entry.author === me ? "you" : entry.author) : null;
  switch (status.source) {
    case "file":
      return `loaded ${formatClock(at)} from the file (edited on disk)`;
    case "panel":
      return `published from the panel ${when}${who ? ` by ${who}` : ""}`;
    case "rollback":
      return `rolled back ${when}${who ? ` by ${who}` : ""}`;
    default:
      return `loaded ${formatClock(at)} when the gateway started`;
  }
}

/** Who made a version: username, "filesystem" for edits on disk, "gateway" at startup. */
export function authorOf(v: PolicyVersion): string {
  if (v.author) return v.author;
  return v.source === "startup" ? "gateway" : "filesystem";
}

export function whenOf(v: PolicyVersion): string {
  return formatWhen(v.created_at);
}

/** Message of an admin-API error: the gateway's `ErrorResponse.message`, FastAPI's `detail`, or the HTTP status. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const b = err.body as { message?: unknown; details?: { errors?: { message?: unknown }[] } } | undefined;
    if (b && typeof b.message === "string") {
      const errs = Array.isArray(b.details?.errors) ? b.details.errors.map((e) => String(e.message ?? "")).filter(Boolean) : [];
      return errs.length && !b.message.includes(errs[0]) ? `${b.message}: ${errs.join("; ")}` : b.message;
    }
    return err.detail;
  }
  return err instanceof Error ? err.message : "Something went wrong";
}

export const isConflict = (err: unknown) => err instanceof ApiError && err.status === 409;

// ---------------------------------------------------------------- dry-run

export interface Transition {
  from: Decision;
  to: Decision;
  count: number;
}

/** `allow->block` → count. Keys that are not transitions (demo `suite:*` extras) are skipped. */
export function transitionsOf(r: DryRunResponse): Transition[] {
  return Object.entries(r.transitions)
    .filter(([k]) => k.includes("->"))
    .map(([k, count]) => {
      const [from, to] = k.split("->") as [Decision, Decision];
      return { from, to, count };
    })
    .filter((t) => t.count > 0);
}

export interface SuiteNumbers {
  asrBefore: number;
  asrAfter: number;
  fprBefore: number;
  fprAfter: number;
  testsPassed: number;
  testsTotal: number;
}

/**
 * Test-suite numbers for the impact box. The contract has no field for them; the demo gateway puts them into
 * `transitions` under `suite:*` keys. Missing → null (the rows are hidden).
 */
export function suiteOf(r: DryRunResponse): SuiteNumbers | null {
  const t = r.transitions;
  const n = (k: string) => (typeof t[`suite:${k}`] === "number" ? t[`suite:${k}`] : undefined);
  const s = {
    asrBefore: n("asr_before"),
    asrAfter: n("asr_after"),
    fprBefore: n("fpr_before"),
    fprAfter: n("fpr_after"),
    testsPassed: n("tests_passed"),
    testsTotal: n("tests_total"),
  };
  return Object.values(s).every((v) => v !== undefined) ? (s as SuiteNumbers) : null;
}

/** "Would have let through 3 of the last 500 requests that were blocked." (template, from the transitions). */
export function impactSentence(r: DryRunResponse): string {
  const ts = transitionsOf(r);
  const of = `of the last ${formatNumber(r.evaluated)} requests`;
  if (ts.length === 0) return `Would not have changed any ${of}.`;
  const sum = (pred: (t: Transition) => boolean) => ts.filter(pred).reduce((a, t) => a + t.count, 0);
  const parts: string[] = [];
  const letThrough = sum((t) => t.from === "block" && t.to !== "block");
  const blocked = sum((t) => t.to === "block" && t.from !== "block");
  const toCloud = sum((t) => t.from === "route_local" && t.to === "allow");
  const toLocal = sum((t) => t.to === "route_local" && t.from !== "route_local");
  if (letThrough) parts.push(`Would have let through ${letThrough} ${of} that were blocked.`);
  if (blocked) parts.push(`Would have blocked ${blocked} more ${of}.`);
  if (toCloud) parts.push(`${toCloud} ${of} would have gone to a cloud model instead of staying local.`);
  if (toLocal) parts.push(`${toLocal} more ${of} would have stayed on local models.`);
  const other = r.changed - letThrough - blocked - toCloud - toLocal;
  if (other > 0) parts.push(`${other} other ${other === 1 ? "decision" : "decisions"} would have changed.`);
  return parts.join(" ");
}

export const pct = (n: number) => `${n.toFixed(1)}%`;

// ---------------------------------------------------------------- diff

export interface DiffLine {
  kind: "add" | "del" | "ctx" | "hunk";
  text: string;
}

export interface DiffFile {
  name: string;
  lines: DiffLine[];
}

/** Parse a unified diff into files and lines. */
export function parseDiff(diff: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | null = null;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("--- ")) continue;
    if (raw.startsWith("+++ ")) {
      cur = { name: raw.slice(4).replace(/^b\//, ""), lines: [] };
      files.push(cur);
      continue;
    }
    if (raw.startsWith("diff ") || raw.startsWith("index ")) continue;
    if (!cur) {
      cur = { name: "", lines: [] };
      files.push(cur);
    }
    if (raw.startsWith("@@")) cur.lines.push({ kind: "hunk", text: raw });
    else if (raw.startsWith("+")) cur.lines.push({ kind: "add", text: raw.slice(1) });
    else if (raw.startsWith("-")) cur.lines.push({ kind: "del", text: raw.slice(1) });
    else if (raw !== "" || cur.lines.length) cur.lines.push({ kind: "ctx", text: raw.slice(1) });
  }
  return files.filter((f) => f.lines.length > 0);
}
