"use client";

import * as React from "react";
import Link from "next/link";
import { BrandLockup } from "@/components/rogatka/brand";
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
      <header className="relative flex flex-wrap items-center gap-x-[18px] gap-y-2 border-b border-border bg-surface px-4 py-2.5 text-[13px]">
        <Link href="/" aria-label="Rogatka Dashboard" className="mr-2 text-text no-underline">
          <BrandLockup />
        </Link>
        <div className="flex-[1_1_20px]" />
        <ProfileMenu shortcutsOpen={shortcutsOpen} onShortcutsOpenChange={setShortcutsOpen} />
        {/* 2 px accent rule along the bottom edge, right of the logo (STYLEGUIDE section 4) */}
        <span aria-hidden data-slot="header-rule" className="pointer-events-none absolute -bottom-px left-[196px] right-0 h-0.5 bg-accent" />
      </header>
      <div className="flex flex-1 flex-wrap items-stretch">
        <SidebarNav />
        <main className="box-border flex min-w-0 flex-[999_1_560px] flex-col gap-3.5 px-6 pb-8 pt-5">{children}</main>
      </div>
    </div>
  );
}
