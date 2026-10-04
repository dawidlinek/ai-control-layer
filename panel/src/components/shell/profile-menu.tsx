"use client";

import * as React from "react";
import { signOut } from "next-auth/react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Avatar } from "@/components/rogatka/avatar";
import { Segmented } from "@/components/rogatka/filters";
import { EmptyState } from "@/components/rogatka/status";
import { ICON_PATHS, PathIcon } from "@/components/rogatka/icon";
import { displayTitle } from "@/lib/auth/user";
import { useDevMode, useSignOutUrl, useUser } from "@/lib/auth/user-context";
import { useTheme, type Theme } from "./theme";
import { ShortcutsDialog } from "./shortcuts";

const ROW = "flex min-h-9 items-center gap-2.5 rounded-[6px] px-2.5";

/** Profile button (initials, name, role) with the account menu. */
export function ProfileMenu({ onOpenShortcuts, shortcutsOpen, onShortcutsOpenChange }: {
  onOpenShortcuts?: () => void;
  shortcutsOpen: boolean;
  onShortcutsOpenChange: (open: boolean) => void;
}) {
  const user = useUser();
  const devMode = useDevMode();
  const signOutUrl = useSignOutUrl();
  const { theme, setTheme } = useTheme();
  const [open, setOpen] = React.useState(false);
  const [notifications, setNotifications] = React.useState(false);
  const title = displayTitle(user);
  const group = user.groups[0];

  async function onSignOut() {
    if (devMode) {
      window.location.assign("/signed-out");
      return;
    }
    await signOut({ redirect: false });
    // Also end the Keycloak SSO session, otherwise the next visit signs straight back in.
    window.location.assign(signOutUrl);
  }

  return (
    <>
      <DropdownMenu open={open} onOpenChange={setOpen}>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label="Account menu"
            className={`inline-flex min-h-9 items-center gap-2 rounded-[20px] border py-0.5 pl-0.5 pr-2.5 text-text ${open ? "border-accent-line bg-accent-soft" : "border-transparent"}`}
          >
            <Avatar name={user.name} size={30} />
            <span className="flex flex-col items-start leading-[1.2]">
              <span className="text-[13.5px]">{user.name}</span>
              <span className="text-[11px] text-muted">{title}</span>
            </span>
            <PathIcon path={open ? ICON_PATHS.chevronUp : ICON_PATHS.chevronDown} size={12} strokeWidth={2.4} />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" aria-label="Account" className="w-[290px]">
          <div className="flex items-center gap-2.5 px-2.5 pb-3 pt-2.5">
            <Avatar name={user.name} size={38} />
            <span className="flex min-w-0 flex-col">
              <b className="truncate font-semibold">{user.name}</b>
              <span className="truncate text-[12px] text-muted">{user.email}</span>
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5 border-b border-border px-2.5 pb-2.5">
            <span className="rounded-[10px] bg-accent-soft px-2 py-px text-[11.5px] text-accent">{title}</span>
            {user.roles.filter((r) => r.startsWith("acl-")).map((r) => (
              <span key={r} className="rounded-[10px] border border-border px-2 py-px font-mono text-[11px] text-muted">
                {r}
              </span>
            ))}
            {group && (
              <span className="rounded-[10px] border border-border px-2 py-px text-[11.5px] text-muted">Keycloak · {group}</span>
            )}
          </div>
          <DropdownMenuItem className={ROW} onSelect={() => setNotifications(true)}>
            <PathIcon path={ICON_PATHS.bell} size={15} strokeWidth={1.9} className="text-muted" />
            <span className="flex-1">Notifications</span>
          </DropdownMenuItem>
          <DropdownMenuItem
            className={ROW}
            onSelect={() => {
              onOpenShortcuts?.();
              onShortcutsOpenChange(true);
            }}
          >
            <PathIcon path={ICON_PATHS.keyboard} size={15} strokeWidth={1.9} className="text-muted" />
            <span className="flex-1">Keyboard shortcuts</span>
            <span className="font-mono text-[11px] text-muted">?</span>
          </DropdownMenuItem>
          <div className="mt-1 flex min-h-10 items-center justify-between gap-2.5 border-t border-border px-2.5">
            <span>Theme</span>
            <Segmented<Theme>
              ariaLabel="Theme"
              size="sm"
              value={theme}
              onChange={setTheme}
              options={[
                { value: "light", label: "Light" },
                { value: "dark", label: "Dark" },
              ]}
            />
          </div>
          <DropdownMenuItem className={`${ROW} mt-px border-t border-border rounded-t-none`} onSelect={() => void onSignOut()}>
            <PathIcon path={ICON_PATHS.signOut} size={15} strokeWidth={1.9} className="text-muted" />
            <span>Sign out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ShortcutsDialog open={shortcutsOpen} onOpenChange={onShortcutsOpenChange} />

      <Dialog open={notifications} onOpenChange={setNotifications}>
        <DialogContent>
          <DialogTitle>Notifications</DialogTitle>
          <DialogDescription>Things that need a person: new incidents, approvals, expiring grants.</DialogDescription>
          <EmptyState title="Nothing needs your attention">New incidents and approvals show up here and in the sidebar counts.</EmptyState>
        </DialogContent>
      </Dialog>
    </>
  );
}
