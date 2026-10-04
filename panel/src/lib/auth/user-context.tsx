"use client";

import * as React from "react";
import { hasRole, parseRole, type Role } from "./roles";
import type { PanelUser } from "./user";

interface UserCtx {
  user: PanelUser;
  /** Dev / mock mode (demo user, `?role=` override available). */
  devMode: boolean;
  /** Where "Sign out" goes. */
  signOutUrl: string;
}

const UserContext = React.createContext<UserCtx | null>(null);
const DEV_ROLE_KEY = "rogatka-dev-role";

const REALM_ROLE: Record<Role, string> = { admin: "acl-admin", analyst: "acl-analyst", viewer: "acl-viewer" };

/**
 * Provides the signed-in user (identity, roles, groups: never tokens) to client components.
 * In dev mode `?role=viewer|analyst|admin` overrides the role for the tab (remembered in sessionStorage),
 * to check how screens look for read-only users.
 */
export function UserProvider({
  user: serverUser,
  devMode = false,
  signOutUrl = "/api/auth/signout",
  children,
}: {
  user: PanelUser;
  devMode?: boolean;
  signOutUrl?: string;
  children: React.ReactNode;
}) {
  const [override, setOverride] = React.useState<Role | null>(null);

  React.useEffect(() => {
    if (!devMode) return;
    let role = parseRole(new URLSearchParams(window.location.search).get("role"));
    try {
      if (role) window.sessionStorage.setItem(DEV_ROLE_KEY, role);
      else role = parseRole(window.sessionStorage.getItem(DEV_ROLE_KEY));
    } catch {
      /* storage may be unavailable */
    }
    if (role) setOverride(role);
  }, [devMode]);

  const value = React.useMemo<UserCtx>(() => {
    const user: PanelUser = override
      ? { ...serverUser, role: override, roles: [REALM_ROLE[override]], title: undefined }
      : serverUser;
    return { user, devMode, signOutUrl };
  }, [serverUser, override, devMode, signOutUrl]);

  return <UserContext.Provider value={value}>{children}</UserContext.Provider>;
}

function useUserCtx(): UserCtx {
  const ctx = React.useContext(UserContext);
  if (!ctx) throw new Error("useUser / useRole must be used inside <UserProvider>");
  return ctx;
}

/** The signed-in user (name, e-mail, roles, groups). */
export function useUser(): PanelUser {
  return useUserCtx().user;
}

export function useSignOutUrl(): string {
  return useUserCtx().signOutUrl;
}

export function useDevMode(): boolean {
  return useUserCtx().devMode;
}

/** The highest panel role of the user: `"admin" | "analyst" | "viewer"` (never `null` inside the shell). */
export function useRole(): Role | null {
  return useUserCtx().user.role;
}

/** `true` when the user's role is at least `min`. Use for enabling / disabling actions. */
export function useHasRole(min: Role): boolean {
  return hasRole(useRole(), min);
}

/**
 * Render children only when the user has at least role `min`; otherwise render `fallback` (default: nothing).
 * Hide admin-only actions from viewers, or pass a disabled button as `fallback`.
 * (The gateway enforces roles too: this is for UX, not security.)
 */
export function RequireRole({
  min,
  fallback = null,
  children,
}: {
  min: Role;
  fallback?: React.ReactNode;
  children: React.ReactNode;
}) {
  return useHasRole(min) ? <>{children}</> : <>{fallback}</>;
}
