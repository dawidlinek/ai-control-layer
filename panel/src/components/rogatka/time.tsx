"use client";

import { cn } from "@/lib/utils";
import { formatAge, formatDay, formatTime, formatWhen } from "@/lib/format";
import { useNow } from "./use-now";

export { formatTime, formatDay, formatWhen, formatAge } from "@/lib/format";

/** Mono time with the day underneath ("14:03:12 / today"), the Traffic table "Time" cell. */
export function TimeCell({ iso, className }: { iso: string; className?: string }) {
  const now = useNow(60_000);
  return (
    <time dateTime={iso} className={cn("flex flex-col leading-[1.25]", className)}>
      <span className="font-mono text-[12px]">{formatTime(iso)}</span>
      <span className="text-[11px] text-muted">{formatDay(iso, now)}</span>
    </time>
  );
}

/** Compact age ("38 m", "1 h", "2 d"); hover shows the absolute time. */
export function RelativeTime({ iso, className }: { iso: string; className?: string }) {
  const now = useNow(30_000);
  return (
    <time dateTime={iso} title={formatWhen(iso, now)} className={cn("font-mono text-[12px]", className)}>
      {formatAge(iso, now)}
    </time>
  );
}
