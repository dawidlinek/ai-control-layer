import type { Approval, User } from "@/lib/api/types";
import { approverLabel, clientApp, parseArguments, reasonsOf, shortAction, type ParsedArguments, type Person } from "./readers";

/** One approval with everything the list and sidebar derive from it. */
export interface ApprovalRow {
  a: Approval;
  parsed: ParsedArguments;
  /** Why it was held, one line per holding control. */
  reasons: string[];
  short: string;
  who: Person;
  /** Second line of the Who column ("OpenCode · developers", "agent"). */
  whoLine: string;
  approver: string;
}

export function toRow(a: Approval, people: Map<string, User> | undefined): ApprovalRow {
  const parsed = parseArguments(a);
  const user = people?.get(a.requested_by);
  const isAgent = user ? user.kind === "agent" : !a.requested_by.includes(".");
  const name = user?.display_name || a.requested_by;
  const app = clientApp(a);
  // An agent's client is its own id: do not repeat the name under the name.
  const clientPart = app && app !== a.requested_by ? app : null;
  const whoLine = [clientPart, isAgent ? "agent" : user?.groups[0]].filter(Boolean).join(" · ");
  return {
    a,
    parsed,
    reasons: reasonsOf(a),
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
