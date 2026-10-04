import "server-only";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { auth } from "@/auth";
import { authMode } from "./mode";
import { refreshKeycloakToken } from "./refresh";
import { roleFromRealmRoles } from "./roles";
import { DEV_USER, type PanelUser } from "./user";

/** The signed-in user for server components, or `null` when nobody is signed in. Dev mode: the demo user. */
export async function getPanelUser(): Promise<PanelUser | null> {
  if (authMode() === "dev") return DEV_USER;
  const session = await auth();
  if (!session?.user || session.error) return null;
  const { name, email, username, roles, groups } = session.user;
  return {
    name: name ?? username ?? email ?? "Unknown",
    email: email ?? "",
    username: username ?? "",
    roles,
    groups,
    role: roleFromRealmRoles(roles),
  };
}

/**
 * Bearer token for the gateway, read from the encrypted session cookie of this request (refreshed when expired).
 * Dev mode: optional `ROGATKA_DEV_TOKEN`. Returns `null` when there is no valid session.
 */
export async function getAccessToken(req: NextRequest): Promise<string | null> {
  if (authMode() === "dev") return process.env.ROGATKA_DEV_TOKEN ?? null;
  const proto = req.headers.get("x-forwarded-proto") ?? req.nextUrl.protocol.replace(":", "");
  const token = await getToken({ req, secret: process.env.AUTH_SECRET, secureCookie: proto === "https" });
  if (!token?.accessToken) return null;
  if (token.expiresAt && Date.now() < (token.expiresAt - 30) * 1000) return token.accessToken;
  const fresh = await refreshKeycloakToken(token);
  return fresh.error ? null : (fresh.accessToken ?? null);
}
