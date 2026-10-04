"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useNavCounts } from "@/lib/api/hooks";
import { NAV, isActive } from "./nav-config";

/** Left navigation (>= 200 px; the shell stacks it above the content on narrow screens). */
export function SidebarNav() {
  const pathname = usePathname() ?? "/";
  const counts = useNavCounts();

  return (
    <nav
      aria-label="Main"
      className="box-border flex flex-[1_1_200px] flex-col gap-3.5 border-r border-border bg-surface px-2.5 py-3.5"
    >
      {NAV.map((section, i) => (
        <div key={section.title ?? i} className="flex flex-col gap-px">
          {section.title && (
            <div className="px-2.5 pb-1 text-[10.5px] font-semibold uppercase tracking-[.08em] text-muted">
              {section.title}
            </div>
          )}
          {section.items.map((item) => {
            const active = isActive(item, pathname);
            const count = item.badge ? counts[item.badge] : undefined;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "box-border flex min-h-8 items-center justify-between gap-2 rounded-[6px] px-2.5 py-1.5 text-[13px] no-underline",
                  active ? "bg-accent-soft font-semibold text-text" : "font-normal text-muted hover:bg-raised hover:text-text",
                )}
              >
                <span>{item.label}</span>
                {count !== undefined && count > 0 && (
                  <span
                    data-badge={item.badge}
                    aria-label={`${count} ${item.badge === "incidents" ? "open" : "pending"}`}
                    className="rounded-[9px] bg-accent-soft px-[7px] text-[11px] font-semibold text-accent"
                  >
                    {count}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
