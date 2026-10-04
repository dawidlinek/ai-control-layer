"use client";

import { signOut } from "next-auth/react";
import { BrandLockup } from "@/components/rogatka/brand";
import { Button } from "@/components/ui/button";
import { useSignOutUrl, useUser } from "@/lib/auth/user-context";

/** Shown to signed-in users who hold none of acl-admin / acl-analyst / acl-viewer. */
export function NoAccess() {
  const user = useUser();
  const signOutUrl = useSignOutUrl();
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="flex w-full max-w-[420px] flex-col gap-3 rounded-[8px] border border-border bg-surface p-6">
        <BrandLockup className="mb-1" />
        <h1 className="m-0 text-[22px] font-semibold tracking-[-0.01em]">No access to Rogatka Dashboard</h1>
        <p className="m-0 text-muted">
          {user.name} ({user.email || user.username}) is signed in, but has none of the roles the dashboard needs:{" "}
          <code className="font-mono text-[12px]">acl-viewer</code>, <code className="font-mono text-[12px]">acl-analyst</code> or{" "}
          <code className="font-mono text-[12px]">acl-admin</code>. Ask an administrator to add you in Keycloak.
        </p>
        <div>
          <Button
            variant="secondary"
            onClick={async () => {
              await signOut({ redirect: false });
              window.location.assign(signOutUrl);
            }}
          >
            Sign out
          </Button>
        </div>
      </div>
    </div>
  );
}
