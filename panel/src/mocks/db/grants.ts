/**
 * Mock data: grants (personal / temporary access on top of group rules) and their change log.
 * From docs/ux/design-reference/Grants.dc.html, adapted to HANDOFF section 6 and the 7.1 lineup:
 * g-0412 Jan's 7-day `smart` (Gemini) pilot, g-0415 bash denied for Anna, budget shares g-0420 / g-0421.
 * Elevations from approvals (apr-0190, apr-0193) are not grants: they live on the approval (`Approval.elevation`).
 * Budget grants: the contract has no "budget" effect; a grant with `constraints.budget_share` is shown as one.
 */
import { daysAgo, demoClock, hoursAgo, inDays, inHours } from "../time";
import { registerReset, seeded } from "./registry";
import type { Grant, GrantChange } from "./types";

type GrantSeed = Omit<Grant, "constraints" | "revoked_at" | "revoked_by" | "active" | "effect"> & {
  effect?: Grant["effect"];
  constraints?: Partial<Grant["constraints"]>;
  revoked_at?: string | null;
  revoked_by?: string | null;
};

function grant(g: GrantSeed): Grant {
  const revoked_at = g.revoked_at ?? null;
  const expired = g.expires_at !== null && new Date(g.expires_at).getTime() <= Date.now();
  return {
    effect: "allow",
    ...g,
    constraints: { data_classes: null, budget_share: null, preset: null, ...g.constraints },
    revoked_at,
    revoked_by: g.revoked_by ?? null,
    active: !revoked_at && !expired,
  };
}

function seedGrants(): Grant[] {
  return [
    grant({
      id: "g-0412",
      subject_type: "user",
      subject: "j.kowalski",
      resource_type: "alias",
      resource: "smart",
      constraints: { data_classes: ["public", "internal"] },
      expires_at: inHours(23),
      reason: "Gemini pilot",
      created_by: "m.zielinska",
      created_at: hoursAgo(7 * 24 - 23),
    }),
    grant({
      id: "g-0415",
      subject_type: "user",
      subject: "a.nowak",
      resource_type: "tool",
      resource: "opencode.bash",
      effect: "deny",
      expires_at: null,
      reason: "No shell needed for loan work",
      created_by: "k.wojcik",
      created_at: demoClock("13:58:00"),
    }),
    grant({
      id: "g-0398",
      subject_type: "user",
      subject: "a.nowak",
      resource_type: "mcp_server",
      resource: "jira",
      expires_at: inDays(27),
      reason: "Jira pilot",
      created_by: "m.zielinska",
      created_at: daysAgo(18),
    }),
    grant({
      id: "g-0420",
      subject_type: "user",
      subject: "j.kowalski",
      resource_type: "alias",
      resource: "auto",
      constraints: { budget_share: 0.2 },
      expires_at: null,
      reason: "team split",
      created_by: "m.zielinska",
      created_at: daysAgo(5),
    }),
    grant({
      id: "g-0421",
      subject_type: "user",
      subject: "p.zielinski",
      resource_type: "alias",
      resource: "auto",
      constraints: { budget_share: 0.3 },
      expires_at: null,
      reason: "team split",
      created_by: "m.zielinska",
      created_at: daysAgo(5),
    }),
    grant({
      id: "g-0402",
      subject_type: "user",
      subject: "m.lis",
      resource_type: "skill",
      resource: "skill/loan-memo-summary",
      constraints: { preset: "strict" },
      expires_at: inDays(6),
      reason: "trying the new skill",
      created_by: "k.wojcik",
      created_at: daysAgo(1),
    }),
    grant({
      id: "g-0391",
      subject_type: "user",
      subject: "t.wisniewski",
      resource_type: "alias",
      resource: "smart-pro",
      constraints: { data_classes: ["public", "internal"] },
      expires_at: daysAgo(2),
      reason: "quarterly report drafting",
      created_by: "m.zielinska",
      created_at: daysAgo(9),
    }),
  ];
}

export const grants = seeded(seedGrants);

function seedChanges(): GrantChange[] {
  const list: GrantChange[] = [];
  let id = 1;
  for (const g of [...grants.items].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
    list.push({ id: id++, grant_id: g.id, change: "create", actor: g.created_by, reason: g.reason, at: g.created_at, snapshot: { ...g } });
    if (g.expires_at && !g.active && !g.revoked_at) {
      list.push({ id: id++, grant_id: g.id, change: "expire", actor: "system", reason: "expired", at: g.expires_at, snapshot: { ...g } });
    }
  }
  return list;
}

export const grantChanges = seeded(seedChanges);

let nextNumber = 422;
registerReset(() => {
  nextNumber = 422;
});

/** Next free grant id (`g-0422`, `g-0423`, ...). */
export function nextGrantId(): string {
  return `g-${String(nextNumber++).padStart(4, "0")}`;
}

/** Append a change to the log (newest last; the handler serves newest first). */
export function recordGrantChange(g: Grant, change: GrantChange["change"], actor: string, reason: string): GrantChange {
  const id = grantChanges.items.reduce((m, c) => Math.max(m, c.id), 0) + 1;
  const entry: GrantChange = { id, grant_id: g.id, change, actor, reason, at: new Date().toISOString(), snapshot: { ...g } };
  grantChanges.items.push(entry);
  return entry;
}

/** Live (not revoked, not expired) grants addressed to a user (username or subject) or one of their groups. */
export function liveGrantsFor(keys: readonly string[], groupNames: readonly string[]): Grant[] {
  const now = Date.now();
  return grants.items.filter(
    (g) =>
      !g.revoked_at &&
      (g.expires_at === null || new Date(g.expires_at).getTime() > now) &&
      (g.subject_type === "user" ? keys.includes(g.subject) : groupNames.includes(g.subject.replace(/^\//, ""))),
  );
}
