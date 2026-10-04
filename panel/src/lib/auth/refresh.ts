import type { JWT } from "next-auth/jwt";
import { realmRolesFromAccessToken } from "./roles";

/** Token endpoint the server uses (internal URL inside Docker, else the public issuer). */
function tokenEndpoint(): string {
  const base = process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER ?? process.env.AUTH_KEYCLOAK_ISSUER ?? "";
  return `${base}/protocol/openid-connect/token`;
}

// A refresh in flight or just done, shared by concurrent requests (key: the refresh token that was spent).
const recent = new Map<string, { at: number; token: Promise<JWT> }>();

/**
 * Exchange the refresh token for a new access token. Returns the updated JWT, or the same JWT with
 * `error: "RefreshTokenError"` when Keycloak refuses (session expired / revoked).
 */
export function refreshKeycloakToken(token: JWT): Promise<JWT> {
  const key = token.refreshToken ?? "";
  const hit = recent.get(key);
  if (hit && Date.now() - hit.at < 10_000) return hit.token;
  const run = doRefresh(token);
  recent.set(key, { at: Date.now(), token: run });
  for (const [k, v] of recent) if (Date.now() - v.at > 60_000) recent.delete(k);
  return run;
}

async function doRefresh(token: JWT): Promise<JWT> {
  try {
    const res = await fetch(tokenEndpoint(), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: process.env.AUTH_KEYCLOAK_ID ?? "panel",
        client_secret: process.env.AUTH_KEYCLOAK_SECRET ?? "",
        refresh_token: token.refreshToken ?? "",
      }),
    });
    const data = (await res.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };
    if (!res.ok || !data.access_token) throw new Error("refresh refused");
    return {
      ...token,
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? token.refreshToken,
      expiresAt: Math.floor(Date.now() / 1000) + (data.expires_in ?? 300),
      roles: realmRolesFromAccessToken(data.access_token),
      error: undefined,
    };
  } catch {
    return { ...token, error: "RefreshTokenError" };
  }
}
