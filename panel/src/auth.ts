/**
 * Auth.js v5 (next-auth@beta) with the Keycloak provider. Configuration is built lazily per request, so the
 * app builds without any auth environment.
 *
 * Tokens (access + refresh) live only in the encrypted JWT cookie. The `session` callback exposes to the
 * browser nothing but name, e-mail, username, roles and groups; server code that needs the bearer token
 * (the `/admin/v1/*` proxy) reads it from the cookie with `getAccessToken` (lib/auth/server.ts).
 *
 * Env: AUTH_SECRET, AUTH_KEYCLOAK_ID (panel), AUTH_KEYCLOAK_SECRET, AUTH_KEYCLOAK_ISSUER (the URL browsers
 * and tokens use, e.g. http://localhost:8180/realms/acl) and optionally AUTH_KEYCLOAK_INTERNAL_ISSUER
 * (how the server reaches Keycloak inside Docker, e.g. http://keycloak:8080/realms/acl), see deploy/compose.panel.yml.
 */
import NextAuth, { type NextAuthConfig } from "next-auth";
import Keycloak from "next-auth/providers/keycloak";
import type { JWT } from "next-auth/jwt";
import { realmRolesFromAccessToken, roleFromRealmRoles } from "@/lib/auth/roles";
import { refreshKeycloakToken } from "@/lib/auth/refresh";

declare module "next-auth" {
  interface Session {
    error?: "RefreshTokenError";
    user: {
      name?: string | null;
      email?: string | null;
      image?: string | null;
      username: string;
      roles: string[];
      groups: string[];
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    refreshToken?: string;
    /** Access token expiry, epoch seconds. */
    expiresAt?: number;
    roles?: string[];
    groups?: string[];
    username?: string;
    error?: "RefreshTokenError";
  }
}

function buildConfig(): NextAuthConfig {
  const issuer = process.env.AUTH_KEYCLOAK_ISSUER;
  const internal = process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER;
  return {
    session: { strategy: "jwt" },
    providers: [
      Keycloak({
        clientId: process.env.AUTH_KEYCLOAK_ID ?? "panel",
        clientSecret: process.env.AUTH_KEYCLOAK_SECRET,
        issuer,
        // Behind Docker the browser-visible issuer is not reachable from the server: keep the public URL for the
        // redirect and for `iss` validation, and use the internal URL for server-to-server calls.
        ...(issuer && internal
          ? {
              authorization: { url: `${issuer}/protocol/openid-connect/auth`, params: { scope: "openid profile email" } },
              token: `${internal}/protocol/openid-connect/token`,
              userinfo: `${internal}/protocol/openid-connect/userinfo`,
              jwks_endpoint: `${internal}/protocol/openid-connect/certs`,
            }
          : {}),
      }),
    ],
    callbacks: {
      async jwt({ token, account, profile }): Promise<JWT> {
        if (account) {
          // First sign-in: keep the tokens, derive roles / groups for the UI.
          return {
            ...token,
            accessToken: account.access_token,
            refreshToken: account.refresh_token,
            expiresAt: account.expires_at,
            roles: realmRolesFromAccessToken(account.access_token),
            groups: Array.isArray((profile as { groups?: unknown } | undefined)?.groups)
              ? ((profile as { groups: string[] }).groups)
              : [],
            username: (profile as { preferred_username?: string } | undefined)?.preferred_username ?? token.email ?? "",
            error: undefined,
          };
        }
        // Still valid (30 s margin)?
        if (token.expiresAt && Date.now() < (token.expiresAt - 30) * 1000) return token;
        if (!token.refreshToken) return { ...token, error: "RefreshTokenError" };
        return refreshKeycloakToken(token);
      },
      async session({ session, token }) {
        // Browser-visible session: identity and roles only. No tokens, ever.
        session.user.username = token.username ?? "";
        session.user.roles = token.roles ?? [];
        session.user.groups = token.groups ?? [];
        if (token.error) session.error = token.error;
        return session;
      },
    },
  };
}

export const { handlers, auth, signIn, signOut } = NextAuth(() => buildConfig());

/** Highest panel role for a session (used by server components). */
export function sessionRole(roles: string[] | undefined) {
  return roleFromRealmRoles(roles);
}
