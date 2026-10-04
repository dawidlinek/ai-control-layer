import { redirect } from "next/navigation";
import { AppShell } from "@/components/shell/app-shell";
import { NoAccess } from "@/components/shell/no-access";
import { authMode } from "@/lib/auth/mode";
import { getPanelUser } from "@/lib/auth/server";
import { UserProvider } from "@/lib/auth/user-context";

/** Keycloak end-session URL (RP-initiated logout) so "Sign out" also ends the SSO session. */
function signOutUrl(): string {
  const issuer = process.env.AUTH_KEYCLOAK_ISSUER;
  const base = process.env.AUTH_URL ?? "";
  if (!issuer) return "/signed-out";
  const params = new URLSearchParams({
    client_id: process.env.AUTH_KEYCLOAK_ID ?? "panel",
    post_logout_redirect_uri: `${base}/signed-out`,
  });
  return `${issuer}/protocol/openid-connect/logout?${params}`;
}

export default async function DashLayout({ children }: { children: React.ReactNode }) {
  const user = await getPanelUser();
  if (!user) redirect("/sign-in");
  const devMode = authMode() === "dev";
  const logout = devMode ? "/signed-out" : signOutUrl();
  return (
    <UserProvider user={user} devMode={devMode} signOutUrl={logout}>
      {user.role ? <AppShell>{children}</AppShell> : <NoAccess />}
    </UserProvider>
  );
}
