/**
 * Grants vocabulary shared by the Grants screen and the People sidebar of Users & groups:
 * how a grant / access item is described (what, limits, expiry, plain sentence), the resource catalogue
 * offered in grant forms, and the LOCK-01 ceiling check. Pure functions: no fetching.
 */
import { formatClock, formatCountdown, formatDay, formatWhen } from "@/lib/format";
import type { Approval, Grant } from "@/lib/api/types";

export type ResourceType = Grant["resource_type"];
export type DataClass = "public" | "internal" | "confidential" | "restricted";
export const DATA_CLASSES: readonly DataClass[] = ["public", "internal", "confidential", "restricted"];
/** Classes LOCK-01 keeps away from cloud models, whatever a grant says. */
export const LOCKED_FOR_CLOUD: readonly DataClass[] = ["confidential", "restricted"];

/** Cloud model aliases and the provider they route to (HANDOFF 7.1: smart = Gemini Flash, smart-pro = Gemini Pro). */
export const CLOUD_TARGET: Record<string, string> = {
  smart: "gemini",
  "smart-pro": "gemini",
  "gemini/flash": "gemini",
  "gemini/pro": "gemini",
};

export const isModelFamily = (t: ResourceType) => t === "alias" || t === "model" || t === "skill";
export const isCloudResource = (resource: string) => resource in CLOUD_TARGET;

/** `bash` for `opencode.bash`; other tool ids unchanged (`web.fetch`). */
export const toolLabel = (id: string) => id.replace(/^opencode\./, "");

/** Chip label of a model in group settings: `smart (gemini)`. */
export const modelChipLabel = (id: string) => (CLOUD_TARGET[id] && !id.includes("/") ? `${id} (${CLOUD_TARGET[id]})` : id);

/** Short item name: `smart → gemini`, `bash`, `jira`, `skill/loan-memo-summary`. */
export function itemLabel(type: ResourceType, resource: string): string {
  if (type === "tool") return toolLabel(resource);
  if ((type === "alias" || type === "model") && CLOUD_TARGET[resource] && !resource.includes("/")) return `${resource} → ${CLOUD_TARGET[resource]}`;
  return resource;
}

/** The "what" of a grant: `model smart → gemini`, `tool bash`, `MCP server jira`, `skill/loan-memo-summary`. */
export function resourceText(type: ResourceType, resource: string): string {
  switch (type) {
    case "alias":
    case "model":
      return `model ${itemLabel(type, resource)}`;
    case "skill":
      return resource.startsWith("skill/") ? resource : `skill ${resource}`;
    case "tool":
      return `tool ${toolLabel(resource)}`;
    case "mcp_server":
      return `MCP server ${resource}`;
    case "connector":
      return `connector ${resource}`;
  }
}

/** Noun phrase for sentences: `the cloud model smart (Gemini)`, `the tool bash`. */
export function resourcePhrase(type: ResourceType, resource: string): string {
  switch (type) {
    case "alias":
    case "model":
      return isCloudResource(resource) ? `the cloud model ${resource} (Gemini)` : `the model ${resource}`;
    case "skill":
      return `the skill ${resource.replace(/^skill\//, "")}`;
    case "tool":
      return `the tool ${toolLabel(resource)}`;
    case "mcp_server":
      return `the MCP server ${resource}`;
    case "connector":
      return `the connector ${resource}`;
  }
}

export type GrantEffectKind = "allow" | "deny" | "budget";

/** The contract has no "budget" effect: a grant with `budget_share` is shown as a budget grant. */
export const effectKind = (g: Pick<Grant, "effect" | "constraints">): GrantEffectKind =>
  g.constraints.budget_share !== null && g.constraints.budget_share !== undefined ? "budget" : g.effect;

export function maxClass(classes: readonly string[] | null | undefined): DataClass | null {
  if (!classes?.length) return null;
  return [...DATA_CLASSES].reverse().find((c) => classes.includes(c)) ?? null;
}

const usd = (n: number) => n.toFixed(2);

/** Budget grant amount per day, from the share of the group's daily budget. */
export function budgetPerDay(share: number, groupBudget: number | null | undefined): string {
  return groupBudget != null ? `${usd(share * groupBudget)} USD / day` : `${Math.round(share * 100)} % of the group budget`;
}

export function limitsText(g: Pick<Grant, "constraints">, group?: { name: string; budget: number | null | undefined }): string {
  const c = g.constraints;
  if (c.budget_share != null) return group?.budget != null ? `of ${group.name} ${usd(group.budget)}` : `${Math.round(c.budget_share * 100)} % share`;
  const parts: string[] = [];
  const top = maxClass(c.data_classes);
  if (top) parts.push(`≤ ${top}`);
  if (c.preset) parts.push(`${c.preset} preset`);
  return parts.join(" · ") || "—";
}

const HOUR = 3_600_000;

/** `never`, `14:57 left`, `in 23 h`, `in 6 d`, `31 Oct`, `expired 13:35`. */
export function expiresText(expiresAt: string | null, now = Date.now()): string {
  if (!expiresAt) return "never";
  const t = new Date(expiresAt).getTime();
  const left = t - now;
  if (left <= 0) return `expired ${formatDay(t, now) === "today" ? formatClock(t) : formatDay(t, now)}`;
  if (left < HOUR) return `${formatCountdown(t, now)} left`;
  if (left < 48 * HOUR) return `in ${Math.round(left / HOUR)} h`;
  if (left < 14 * 24 * HOUR) return `in ${Math.round(left / (24 * HOUR))} d`;
  return formatDay(t, now);
}

/** Active and ending within 24 h (shown orange). */
export const expiresSoon = (expiresAt: string | null, active: boolean, now = Date.now()) =>
  active && !!expiresAt && new Date(expiresAt).getTime() - now < 24 * HOUR && new Date(expiresAt).getTime() > now;

/** One row of the Grants list: a grant from the DB or a time-boxed elevation from an approval. */
export interface GrantRowView {
  id: string;
  source: "grant" | "elevation";
  grant?: Grant;
  approval?: Approval;
  subjectType: "user" | "group";
  /** Username or group name. */
  subject: string;
  who: string;
  effect: GrantEffectKind;
  resourceType: ResourceType;
  resource: string;
  what: string;
  limits: string;
  expiresAt: string | null;
  active: boolean;
  revoked: boolean;
  reason: string;
  createdBy: string;
  createdAt: string;
}

export interface Directory {
  /** username → display name */
  names: Map<string, string>;
  /** group → daily budget */
  budgets: Map<string, number | null>;
  /** username → first group */
  groupOf: Map<string, string>;
}

export function grantRow(g: Grant, dir: Directory): GrantRowView {
  const effect = effectKind(g);
  const group = g.subject_type === "group" ? g.subject.replace(/^\//, "") : dir.groupOf.get(g.subject);
  const groupInfo = group ? { name: group, budget: dir.budgets.get(group) } : undefined;
  return {
    id: g.id,
    source: "grant",
    grant: g,
    subjectType: g.subject_type,
    subject: g.subject.replace(/^\//, ""),
    who: g.subject_type === "group" ? `group ${g.subject.replace(/^\//, "")}` : (dir.names.get(g.subject) ?? g.subject),
    effect,
    resourceType: g.resource_type,
    resource: g.resource,
    what: effect === "budget" ? budgetPerDay(g.constraints.budget_share ?? 0, groupInfo?.budget) : resourceText(g.resource_type, g.resource),
    limits: limitsText(g, groupInfo),
    expiresAt: g.expires_at,
    active: g.active,
    revoked: !!g.revoked_at,
    reason: g.reason,
    createdBy: g.created_by,
    createdAt: g.created_at,
  };
}

/** `tool:opencode.bash` → ["tool", "opencode.bash"]. */
function parseScope(scope: string): [ResourceType, string] {
  const [kind, ...rest] = scope.split(":");
  const value = rest.join(":") || scope;
  const type: ResourceType = kind === "model" || kind === "alias" || kind === "skill" || kind === "connector" || kind === "mcp_server" ? kind : "tool";
  return [type, value];
}

export function elevationRow(a: Approval, dir: Directory, now = Date.now()): GrantRowView | null {
  if (!a.elevation) return null;
  const [type, resource] = parseScope(a.elevation.scope);
  return {
    id: a.id,
    source: "elevation",
    approval: a,
    subjectType: "user",
    subject: a.requested_by,
    who: dir.names.get(a.requested_by) ?? a.requested_by,
    effect: "allow",
    resourceType: type,
    resource,
    what: resourceText(type, resource),
    limits: a.session_id ? `session ${a.session_id}` : "this session only",
    expiresAt: a.elevation.until,
    active: new Date(a.elevation.until).getTime() > now,
    revoked: false,
    reason: `approved request ${a.id}`,
    createdBy: a.decided_by ?? "—",
    createdAt: a.decided_at ?? a.created_at,
  };
}

/** The plain sentence at the top of the grant sidebar (template, never generated text). */
export function grantSentence(r: GrantRowView, opts: { groupAllows?: string | null; now?: number } = {}): string {
  const now = opts.now ?? Date.now();
  const until = r.expiresAt ? ` until ${formatWhen(r.expiresAt, now)}` : "";
  const ended = r.revoked ? " It has been revoked." : !r.active ? " It has expired." : "";
  if (r.source === "elevation") {
    const session = r.approval?.session_id ? ` in session ${r.approval.session_id}` : "";
    return `A time-boxed elevation from approval ${r.id} lets ${r.who} use ${resourcePhrase(r.resourceType, r.resource)}${session}${r.active ? until : ""}.${ended}`;
  }
  const g = r.grant!;
  if (r.effect === "budget") {
    return `${r.who} gets ${r.what.replace(" / day", " a day")} from the ${r.limits.replace(/^of /, "").replace(/ ([\d.]+)$/, " budget of $1 USD")}.${ended}`;
  }
  if (r.effect === "deny") {
    const although = opts.groupAllows ? `, although the group ${opts.groupAllows} allows it` : "";
    return `${r.who} may not use ${resourcePhrase(r.resourceType, r.resource)}${although}${until}.${ended}`;
  }
  const classes = g.constraints.data_classes?.length ? ` for ${joinAnd(g.constraints.data_classes)} data` : "";
  return `${r.who} may use ${resourcePhrase(r.resourceType, r.resource)}${classes}${until}.${ended}`;
}

export function joinAnd(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** LOCK-01 ceiling check of a grant draft. */
export function ceilingCheck(d: { effect: "allow" | "deny"; resourceType: ResourceType; resource: string; dataClasses: readonly string[] }):
  | { ok: true; message: string }
  | { ok: false; message: string } {
  if (d.effect === "deny") return { ok: true, message: "A denial overrides what the group allows. Org locks still apply." };
  if (isModelFamily(d.resourceType) && isCloudResource(d.resource)) {
    const locked = d.dataClasses.filter((c) => (LOCKED_FOR_CLOUD as readonly string[]).includes(c));
    if (locked.length) {
      return {
        ok: false,
        message: `Blocked by LOCK-01: cloud models never get ${joinAnd(locked)} data, whatever a grant says. Untick ${locked.length > 1 ? "them" : "it"} or choose a local model.`,
      };
    }
    return { ok: true, message: "Within the limits. Cloud models can only get public and internal data (LOCK-01)." };
  }
  return { ok: true, message: "Within the limits." };
}

/** Resources offered in grant forms (HANDOFF 7.1 lineup + tools.yaml ids). */
export interface ResourceOption {
  value: string;
  type: ResourceType;
  resource: string;
  label: string;
}

const opt = (type: ResourceType, resource: string): ResourceOption => ({
  value: `${type}:${resource}`,
  type,
  resource,
  label: resourceText(type, resource),
});

export const RESOURCE_OPTIONS: readonly ResourceOption[] = [
  opt("alias", "smart"),
  opt("alias", "smart-pro"),
  opt("alias", "local"),
  opt("alias", "fast"),
  opt("alias", "local/loan-memo"),
  opt("skill", "skill/loan-memo-summary"),
  opt("tool", "opencode.bash"),
  opt("tool", "opencode.edit"),
  opt("tool", "opencode.write"),
  opt("tool", "web.fetch"),
  opt("tool", "mail.send"),
  opt("tool", "bank.query"),
  opt("mcp_server", "jira"),
  opt("mcp_server", "files"),
  opt("mcp_server", "core-banking"),
];

export function parseResourceValue(value: string): { type: ResourceType; resource: string } {
  const i = value.indexOf(":");
  return { type: value.slice(0, i) as ResourceType, resource: value.slice(i + 1) };
}

export type ExpiryChoice = "1 d" | "7 d" | "30 d" | "never";
const DAYS: Record<Exclude<ExpiryChoice, "never">, number> = { "1 d": 1, "7 d": 7, "30 d": 30 };

export function expiresAtFor(choice: ExpiryChoice, now = Date.now()): string | null {
  return choice === "never" ? null : new Date(now + DAYS[choice] * 24 * HOUR).toISOString();
}
