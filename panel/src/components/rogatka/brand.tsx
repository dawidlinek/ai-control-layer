import * as React from "react";
import { cn } from "@/lib/utils";
import { RogatkaMark } from "./icon";

/** The Szlaban mark on a rounded ink tile (STYLEGUIDE section 1: white on black, radius ~ 22 % of the tile). */
export function LogoTile({ size = 32, className }: { size?: number; className?: string }) {
  return (
    <span
      data-slot="logo-tile"
      className={cn("inline-flex shrink-0 items-center justify-center bg-ink text-on-ink", className)}
      style={{ width: size, height: size, borderRadius: Math.round(size * 0.225) }}
    >
      <RogatkaMark size={Math.round(size * 0.62)} />
    </span>
  );
}

/** Filled accent box with white text, like the red word box in last year's logo. */
export function BrandTag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      data-slot="brand-tag"
      className={cn("inline-block rounded-[2px] bg-accent-text px-1 py-px text-[10.5px] font-bold uppercase leading-[1.25] tracking-[.06em] text-on-accent", className)}
    >
      {children}
    </span>
  );
}

/**
 * Logo lockup: tile + "Rogatka" (600) above a red tag. Dashboard: tag "Dashboard".
 * Use `inline` for a one-line version next to a heading.
 */
export function BrandLockup({ tag = "Dashboard", size = 32, className }: { tag?: string; size?: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <LogoTile size={size} />
      <span className="flex flex-col items-start gap-[3px] leading-none">
        <span className="text-[16px] font-semibold tracking-[-0.01em] text-text">Rogatka</span>
        <BrandTag>{tag}</BrandTag>
      </span>
    </span>
  );
}
