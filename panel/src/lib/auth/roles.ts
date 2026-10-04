/**
 * Panel roles, from Keycloak realm roles in the access token (`realm_access.roles`):
 * `acl-admin` > `acl-analyst` > `acl-viewer`. Pure functions: safe on server, client and edge.
 */
export type Role = "viewer" | "analyst" | "admin";

const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

const REALM_ROLE: Array<[string, Role]> = [
  ["acl-admin", "admin"],
  ["acl-analyst", "analyst"],
  ["acl-viewer", "viewer"],
];

export const ROLE_LABEL: Record<Role, string> = {
  admin: "Administrator",
  analyst: "Security analyst",
  viewer: "Viewer",
};

/** Highest panel role among the realm roles, or `null` when the user has none (-> "No access" page). */
export function roleFromRealmRoles(realmRoles: readonly string[] | undefined | null): Role | null {
  if (!realmRoles) return null;
  for (const [name, role] of REALM_ROLE) if (realmRoles.includes(name)) return role;
  return null;
}

/** `true` when `role` is at least `min` (admin >= analyst >= viewer). `null` never passes. */
export function hasRole(role: Role | null | undefined, min: Role): boolean {
  return !!role && RANK[role] >= RANK[min];
}

export function parseRole(value: string | null | undefined): Role | null {
  return value === "viewer" || value === "analyst" || value === "admin" ? value : null;
}

/** Decode (not verify) the payload of a JWT. The gateway verifies tokens; the panel only reads claims for UI. */
export function decodeJwtPayload(token: string | undefined | null): Record<string, unknown> {
  if (!token) return {};
  try {
    const part = token.split(".")[1];
    if (!part) return {};
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    const json = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    const bytes = Uint8Array.from(json, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function realmRolesFromAccessToken(token: string | undefined | null): string[] {
  const claims = decodeJwtPayload(token) as { realm_access?: { roles?: unknown } };
  const roles = claims.realm_access?.roles;
  return Array.isArray(roles) ? roles.filter((r): r is string => typeof r === "string") : [];
}
