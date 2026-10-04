/**
 * MSW handlers: users and groups (Users & groups screen): lists, user detail, effective access (computed from
 * the group settings + live grants, so a new grant or a deny shows up at once), activity, and group settings
 * preview / save (a save creates the next policy version, like the gateway's policy writer).
 * Change strings follow the gateway (acl/policy/groups_edit.py): `preset a → b`, `+ model smart`, `- tool opencode.bash`,
 * `cloud data internal → public`, `daily budget 5 → 6 USD`.
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import type { components } from "@/lib/api/schema";
import { events } from "../db/events";
import { grantChanges, liveGrantsFor } from "../db/grants";
import { policyStatus } from "../db/policy";
import type { EffectiveAccess, GroupSettings } from "../db/types";
import { findGroup, findUser, groups, MODEL_CATALOGUE, users } from "../db/users";
import { adminPath, intParam, problem, queryOf } from "./helpers";

type GroupSettingsUpdate = components["schemas"]["GroupSettingsUpdate"];
type Item = EffectiveAccess["items"][number];

const CLOUD = new Set(MODEL_CATALOGUE.filter((m) => m.cloud).map((m) => m.id));
const NO_CONSTRAINTS = { data_classes: null, budget_share: null, preset: null };

function effectiveAccess(userId: string): EffectiveAccess | null {
  const u = findUser(userId);
  if (!u) return null;
  const byKey = new Map<string, Item>();
  const extra: Item[] = [];
  for (const name of u.groups) {
    const s = findGroup(name)?.settings;
    if (!s) continue;
    for (const m of s.models) {
      byKey.set(`model:${m}`, {
        resource_type: m.startsWith("skill/") ? "skill" : "alias",
        resource: m,
        effect: "allow",
        source: "group",
        source_ref: name,
        expires_at: null,
        constraints: NO_CONSTRAINTS,
        capped_by_lock: CLOUD.has(m) ? "LOCK-01" : null,
      });
    }
    for (const t of s.tools) {
      byKey.set(`tool:${t}`, { resource_type: "tool", resource: t, effect: "allow", source: "group", source_ref: name, expires_at: null, constraints: NO_CONSTRAINTS, capped_by_lock: null });
    }
  }
  for (const g of liveGrantsFor([u.username, u.subject, u.id], u.groups)) {
    const item: Item = {
      resource_type: g.resource_type,
      resource: g.resource,
      effect: g.effect,
      source: g.subject_type === "user" ? "user" : "group",
      source_ref: g.id,
      expires_at: g.expires_at,
      constraints: g.constraints,
      capped_by_lock: g.effect === "allow" && CLOUD.has(g.resource) ? "LOCK-01" : null,
    };
    if (g.constraints.budget_share !== null) {
      extra.push(item);
      continue;
    }
    const family = g.resource_type === "alias" || g.resource_type === "model" || g.resource_type === "skill" ? "model" : g.resource_type;
    byKey.set(`${family}:${g.resource}`, item);
  }
  const group = u.groups.map(findGroup).find((g) => g?.settings);
  return {
    subject: u.subject,
    username: u.username,
    groups: u.groups,
    preset: u.preset ?? "balanced",
    preset_source: group ? `group ${group.name}` : "default",
    items: [...byKey.values(), ...extra],
    budgets: group?.settings?.daily_budget_usd != null ? { [`group:${group.name}`]: { usd_day: group.settings.daily_budget_usd } } : {},
    policy_version: policyStatus.version,
    grants_version: String(grantChanges.items.length),
  };
}

const num = (n: number | null | undefined) => (n === null || n === undefined ? "none" : String(n));

/** What saving `next` over `current` would change, in the gateway's wording, and which files it writes. */
function planChanges(current: GroupSettings, next: GroupSettings): { changes: string[]; files: string[] } {
  const changes: string[] = [];
  const files = new Set<string>();
  if (next.preset !== current.preset) {
    changes.push(`preset ${current.preset ?? "default"} → ${next.preset ?? "default"}`);
    files.add("groups.yaml");
  }
  const addedModels = next.models.filter((m) => !current.models.includes(m));
  const removedModels = current.models.filter((m) => !next.models.includes(m));
  changes.push(...addedModels.map((m) => `+ model ${m}`), ...removedModels.map((m) => `- model ${m}`));
  const addedTools = next.tools.filter((t) => !current.tools.includes(t));
  const removedTools = current.tools.filter((t) => !next.tools.includes(t));
  changes.push(...addedTools.map((t) => `+ tool ${t}`), ...removedTools.map((t) => `- tool ${t}`));
  if (addedModels.length + removedModels.length + addedTools.length + removedTools.length > 0) files.add("groups.yaml");
  if (next.max_cloud_data_class !== current.max_cloud_data_class) {
    changes.push(`cloud data ${current.max_cloud_data_class} → ${next.max_cloud_data_class}`);
    files.add("groups.yaml");
  }
  if ((next.daily_budget_usd ?? null) !== (current.daily_budget_usd ?? null)) {
    changes.push(`daily budget ${num(current.daily_budget_usd)} → ${num(next.daily_budget_usd)}${next.daily_budget_usd != null ? " USD" : ""}`);
    files.add("budgets.yaml");
  }
  return { changes, files: [...files] };
}

function validate(name: string, s: GroupSettings) {
  const cloud = s.models.filter((m) => CLOUD.has(m));
  if (s.max_cloud_data_class === "none" && cloud.length > 0) {
    return [
      {
        file: "groups.yaml",
        path: `groups.${name}.models`,
        line: null,
        column: null,
        message: `remove cloud models first or allow public/internal data (cloud models: ${cloud.join(", ")})`,
      },
    ];
  }
  return [];
}

const nextVersion = (v: string) => {
  const n = Number(v.replace(/^v/, ""));
  return Number.isFinite(n) ? `v${n + 1}` : `${v}+1`;
};

function normalise(s: Partial<GroupSettings> | undefined, current: GroupSettings): GroupSettings {
  return {
    preset: s?.preset ?? null,
    models: s?.models ?? [],
    tools: s?.tools ?? [],
    max_cloud_data_class: s?.max_cloud_data_class ?? current.max_cloud_data_class,
    daily_budget_usd: s?.daily_budget_usd ?? null,
  };
}

export const usersHandlers: HttpHandler[] = [
  http.get(adminPath("/users"), ({ request }) => {
    const q = queryOf(request);
    const text = q.get("q")?.toLowerCase();
    const group = q.get("group")?.replace(/^\//, "");
    const list = users.items
      .filter((u) => (group ? u.groups.includes(group) : true))
      .filter((u) => (text ? [u.username, u.display_name, u.email].some((v) => v?.toLowerCase().includes(text)) : true))
      .slice(0, intParam(q, "limit", 100));
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/users/:id/effective-access"), ({ params }) => {
    const access = effectiveAccess(String(params.id));
    return access ? HttpResponse.json(access) : problem(404, "user not found");
  }),

  http.get(adminPath("/users/:id/activity"), ({ params, request }) => {
    const u = findUser(String(params.id));
    if (!u) return problem(404, "user not found");
    const limit = intParam(queryOf(request), "limit", 20);
    const list = events.items
      .filter((e) => e.subject === u.subject || e.username === u.username)
      .sort((a, b) => b.seq - a.seq)
      .slice(0, limit);
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/users/:id"), ({ params }) => {
    const u = findUser(String(params.id));
    return u ? HttpResponse.json(u) : problem(404, "user not found");
  }),

  http.get(adminPath("/groups"), () => HttpResponse.json(groups.items)),

  http.get(adminPath("/groups/:name/detail"), ({ params }) => {
    const g = findGroup(String(params.name));
    return g ? HttpResponse.json(g) : problem(404, "group not found");
  }),

  http.post(adminPath("/groups/:name/settings/preview"), async ({ params, request }) => {
    const g = findGroup(String(params.name));
    if (!g?.settings) return problem(404, "group not found");
    const body = (await request.json()) as GroupSettingsUpdate;
    const next = normalise(body.settings, g.settings);
    const errors = validate(g.name, next);
    if (errors.length) return HttpResponse.json({ valid: false, errors, changes: [], files_changed: [], diff: "", candidate_version: null, impact: null });
    const { changes, files } = planChanges(g.settings, next);
    return HttpResponse.json({
      valid: true,
      errors: [],
      changes,
      files_changed: files,
      diff: "",
      candidate_version: changes.length ? nextVersion(policyStatus.version) : policyStatus.version,
      impact: null,
    });
  }),

  http.put(adminPath("/groups/:name/settings"), async ({ params, request }) => {
    const g = findGroup(String(params.name));
    if (!g?.settings) return problem(404, "group not found");
    const body = (await request.json()) as GroupSettingsUpdate;
    if (body.base_version !== policyStatus.version) {
      return problem(409, `policy changed since you started editing (now ${policyStatus.version}); reload and try again`);
    }
    const next = normalise(body.settings, g.settings);
    const errors = validate(g.name, next);
    if (errors.length) return problem(422, errors[0].message);
    const { changes } = planChanges(g.settings, next);
    if (changes.length === 0) return HttpResponse.json(policyStatus);
    g.settings = next;
    g.preset = next.preset;
    for (const u of users.items) if (u.groups.includes(g.name) && next.preset) u.preset = next.preset;
    const at = new Date().toISOString();
    Object.assign(policyStatus, {
      version: nextVersion(policyStatus.version),
      loaded_at: at,
      source: "panel",
      files: policyStatus.files.map((f) =>
        f.name === "groups.yaml" || (f.name === "budgets.yaml" && changes.some((c) => c.startsWith("daily budget"))) ? { ...f, modified_at: at } : f,
      ),
    });
    return HttpResponse.json(policyStatus);
  }),
];
