/**
 * The person's Access list ("kind · item · where it comes from · expiry · action"), built from the
 * effective-access response, the person's grants (for reasons), their group and approved elevations.
 */
import type { Approval, EffectiveAccess, Grant, Group } from "@/lib/api/types";
import {
  budgetPerDay,
  CLOUD_TARGET,
  isCloudResource,
  isModelFamily,
  itemLabel,
  maxClass,
  type ResourceType,
} from "@/features/grants/model";

export type AccessState = "ok" | "no" | "elevated" | "none" | "value";

export type AccessAction =
  | { type: "grant"; resourceType: ResourceType; resource: string }
  | { type: "revoke"; grantId: string; label: string }
  | { type: "restore"; grantId: string; label: string }
  | { type: "deny"; resourceType: ResourceType; resource: string; label: string };

export interface AccessRow {
  key: string;
  kind: "Model" | "Skill" | "Tool" | "MCP" | "Connector" | "Budget" | "Cloud";
  item: string;
  state: AccessState;
  source: string;
  expiresAt: string | null;
  /** The item came from a grant made in this visit (highlighted). */
  fresh?: boolean;
  action?: AccessAction;
}

const KIND: Record<ResourceType, AccessRow["kind"]> = {
  alias: "Model",
  model: "Model",
  skill: "Skill",
  tool: "Tool",
  mcp_server: "MCP",
  connector: "Connector",
};

const ORDER: AccessRow["kind"][] = ["Model", "Skill", "Tool", "MCP", "Connector", "Budget", "Cloud"];

/** Cloud aliases a person can be granted from the Access list when they do not have them. */
export const GRANTABLE_CLOUD = Object.keys(CLOUD_TARGET).filter((k) => !k.includes("/"));

export function buildAccessRows({
  access,
  grants,
  group,
  elevations,
  fresh,
}: {
  access: EffectiveAccess;
  grants: readonly Grant[];
  group: Group | undefined;
  elevations: readonly Approval[];
  fresh: ReadonlySet<string>;
}): AccessRow[] {
  const rows: AccessRow[] = [];
  const byId = new Map(grants.map((g) => [g.id, g]));
  const groupLine = (name: string) =>
    group && group.name === name && group.policy_line ? `group ${name} · ${group.policy_file ?? "groups.yaml"} L${group.policy_line}` : `group ${name}`;
  const groupHas = (type: ResourceType, resource: string) =>
    !!group?.settings && (type === "tool" ? group.settings.tools : group.settings.models).includes(resource);

  for (const it of access.items) {
    const kind = KIND[it.resource_type];
    if (it.constraints.budget_share !== null && it.constraints.budget_share !== undefined) {
      rows.push({
        key: `budget:${it.source_ref}`,
        kind: "Budget",
        item: budgetPerDay(it.constraints.budget_share, group?.settings?.daily_budget_usd),
        state: "value",
        source: `grant ${it.source_ref} · share of ${group?.name ?? "the group"}`,
        expiresAt: it.expires_at,
      });
      continue;
    }
    const base = {
      key: `${it.resource_type}:${it.resource}`,
      kind,
      item: itemLabel(it.resource_type, it.resource),
      expiresAt: it.expires_at,
      fresh: fresh.has(it.source_ref),
    };
    if (it.source === "group" && !byId.has(it.source_ref)) {
      rows.push({
        ...base,
        state: it.effect === "allow" ? "ok" : "no",
        source: groupLine(it.source_ref),
        action: it.resource_type === "tool" && it.effect === "allow" ? { type: "deny", resourceType: it.resource_type, resource: it.resource, label: "Revoke" } : undefined,
      });
    } else if (it.source === "org_lock" || it.source === "default") {
      rows.push({ ...base, state: it.effect === "allow" ? "ok" : "no", source: it.source === "org_lock" ? `org lock ${it.source_ref}` : "default" });
    } else {
      const g = byId.get(it.source_ref);
      const reason = g ? ` · “${g.reason}”` : "";
      const top = maxClass(it.constraints.data_classes);
      if (it.effect === "deny") {
        rows.push({
          ...base,
          state: "no",
          source: `user deny ${it.source_ref}${groupHas(it.resource_type, it.resource) ? " · overrides group" : reason}`,
          action: { type: "restore", grantId: it.source_ref, label: "Restore" },
        });
      } else {
        rows.push({
          ...base,
          state: "ok",
          source: `${it.source === "group" ? "group grant" : "grant"} ${it.source_ref}${reason}${top ? ` · ≤ ${top}` : ""}`,
          action: { type: "revoke", grantId: it.source_ref, label: "Revoke" },
        });
      }
    }
  }

  const allowedModels = new Set(access.items.filter((i) => i.effect === "allow" && isModelFamily(i.resource_type)).map((i) => i.resource));
  for (const m of GRANTABLE_CLOUD) {
    if (allowedModels.has(m) || access.items.some((i) => i.resource === m && i.effect === "deny")) continue;
    rows.push({
      key: `missing:${m}`,
      kind: "Model",
      item: itemLabel("alias", m),
      state: "none",
      source: group ? `not in group ${group.name}` : "not granted",
      expiresAt: null,
      action: { type: "grant", resourceType: "alias", resource: m },
    });
  }

  const now = Date.now();
  for (const a of elevations) {
    if (!a.elevation || new Date(a.elevation.until).getTime() <= now) continue;
    const [scopeKind, ...rest] = a.elevation.scope.split(":");
    const resource = rest.join(":");
    rows.push({
      key: `elevation:${a.id}`,
      kind: scopeKind === "tool" ? "Tool" : "Model",
      item: `${itemLabel(scopeKind === "tool" ? "tool" : "alias", resource)}${a.arguments_preview ? ` · ${a.arguments_preview}` : ""}`,
      state: "elevated",
      source: `approved ${a.id} by ${a.decided_by ?? "—"}`,
      expiresAt: a.elevation.until,
    });
  }

  const cloud = group?.settings?.max_cloud_data_class;
  if (cloud) {
    rows.push({
      key: "cloud",
      kind: "Cloud",
      item: cloud === "none" ? "no cloud models" : `up to ${cloud}`,
      state: "value",
      source: "org lock LOCK-01",
      expiresAt: null,
    });
  }

  return rows.sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind));
}

/** Models the person's clients list (allowed aliases, models and skills; budget-only grants excluded). */
export function clientModels(access: EffectiveAccess): { id: string; sourceRef: string; cloud: boolean }[] {
  const seen = new Set<string>();
  const out: { id: string; sourceRef: string; cloud: boolean }[] = [];
  for (const it of access.items) {
    if (it.effect !== "allow" || !isModelFamily(it.resource_type) || it.constraints.budget_share != null) continue;
    if (seen.has(it.resource)) continue;
    seen.add(it.resource);
    out.push({ id: it.resource, sourceRef: it.source_ref, cloud: isCloudResource(it.resource) });
  }
  return out;
}
