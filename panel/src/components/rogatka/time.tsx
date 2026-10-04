"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { formatAge, formatDay, formatTime, formatWhen } from "@/lib/format";

export { formatTime, formatDay, formatWhen, formatAge } from "@/lib/format";

/** Re-render every `intervalMs` so relative labels stay fresh. */
function useNow(intervalMs: number): number {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

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
