import * as React from "react";
import { cn } from "@/lib/utils";

/** Up to two initials from a display name or username ("Katarzyna Wójcik" -> "KW", "k.wojcik" -> "KW"). */
export function initialsOf(name: string): string {
  const parts = name
    .trim()
    .split(/[\s._-]+/)
    .filter(Boolean);
  if (parts.length === 0) return "?";
  const letters = parts.length === 1 ? parts[0].slice(0, 2) : parts[0][0] + parts[parts.length - 1][0];
  return letters.toUpperCase();
}

/** Round initials avatar on the accent-soft surface. */
export function Avatar({
  name,
  size = 30,
  className,
}: {
  name: string;
  size?: number;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      data-avatar
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-full bg-accent-soft font-semibold text-text",
        className,
      )}
      style={{ width: size, height: size, fontSize: Math.max(10, Math.round(size * 0.37)) }}
    >
      {initialsOf(name)}
    </span>
  );
}
