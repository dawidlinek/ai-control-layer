/**
 * Auth mode. `dev`: no Keycloak, a fixed demo user is signed in (used with the MSW mock API).
 * Default is `dev` when NEXT_PUBLIC_API_MOCKING=enabled, otherwise `keycloak`; override with ROGATKA_AUTH.
 * Read at request time on the server (never captured at build time except for the NEXT_PUBLIC_ flag).
 */
export type AuthMode = "dev" | "keycloak";

export function authMode(): AuthMode {
  const explicit = process.env.ROGATKA_AUTH;
  if (explicit === "dev" || explicit === "keycloak") return explicit;
  return process.env.NEXT_PUBLIC_API_MOCKING === "enabled" ? "dev" : "keycloak";
}

export const isMockingEnabled = () => process.env.NEXT_PUBLIC_API_MOCKING === "enabled";
