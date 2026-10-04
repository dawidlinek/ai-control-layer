"use client";

import * as React from "react";
import Link from "next/link";
import { RogatkaMark } from "@/components/rogatka/icon";
import { ProfileMenu } from "./profile-menu";
import { SidebarNav } from "./sidebar-nav";
import { useGlobalShortcuts } from "./shortcuts";

/**
 * The Rogatka Dashboard frame: top bar (logo lockup, profile menu), left navigation, content.
 * Below ~760 px the navigation stacks above the content (flex wrap, as in the prototypes).
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const [shortcutsOpen, setShortcutsOpen] = React.useState(false);
  useGlobalShortcuts(() => setShortcutsOpen(true));

  return (
    <div className="flex min-h-screen flex-col bg-bg text-text">
      <header className="flex flex-wrap items-center gap-x-[18px] gap-y-2 border-b border-border bg-surface px-4 py-2 text-[12.5px]">
        <Link href="/" className="mr-2 flex items-center gap-2 text-[13.5px] font-semibold text-text no-underline">
          <span className="inline-flex size-6 items-center justify-center rounded-[6px] bg-accent text-on-accent">
            <RogatkaMark size={16} />
          </span>
          <span>
            Rogatka <span className="font-normal text-muted">Dashboard</span>
          </span>
        </Link>
        <div className="flex-[1_1_20px]" />
        <ProfileMenu shortcutsOpen={shortcutsOpen} onShortcutsOpenChange={setShortcutsOpen} />
      </header>
      <div className="flex flex-1 flex-wrap items-stretch">
        <SidebarNav />
        <main className="box-border flex min-w-0 flex-[999_1_560px] flex-col gap-3.5 px-6 pb-8 pt-5">{children}</main>
      </div>
    </div>
  );
}
