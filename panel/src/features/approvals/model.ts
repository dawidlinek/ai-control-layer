import type { Approval, User } from "@/lib/api/types";
import {
  approverLabel,
  clientApp,
  parseArguments,
  parseReason,
  shortAction,
  type ApproverLabel,
  type ParsedArguments,
  type ParsedReason,
  type Person,
} from "./readers";

/** One approval with everything the list and sidebar derive from it. */
export interface ApprovalRow {
  a: Approval;
  parsed: ParsedArguments;
  reason: ParsedReason;
  short: string;
  who: Person;
  /** Second line of the Who column ("OpenCode · developers", "agent for Anna Nowak"). */
  whoLine: string;
  approver: ApproverLabel;
}

export function toRow(a: Approval, people: Map<string, User> | undefined): ApprovalRow {
  const parsed = parseArguments(a);
  const user = people?.get(a.requested_by);
  const isAgent = user ? user.kind === "agent" : !a.requested_by.includes(".");
  const name = user?.display_name || a.requested_by;
  const group = user?.groups[0];
  const app = clientApp(a);
  const whoLine = parsed.client ?? ([app, group].filter(Boolean).join(" · ") || a.server || "");
  return {
    a,
    parsed,
    reason: parseReason(a),
    short: shortAction(a, parsed.command),
    who: { name, isAgent },
    whoLine,
    approver: approverLabel(a),
  };
}

/** Decided within the last 24 h (the "Decided · 24 h" tab). */
export function decidedRecently(a: Approval, now: number): boolean {
  if (a.status === "pending") return false;
  const at = Date.parse(a.decided_at ?? a.created_at);
  return now - at <= 24 * 3600_000;
}
