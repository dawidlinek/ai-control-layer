"use client";

import * as React from "react";

/**
 * Current time in ms, re-rendered every `intervalMs` (live countdowns, relative labels).
 * Pass `active = false` to stop ticking (the value then stays at the last tick).
 */
export function useNow(intervalMs = 1000, active = true): number {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs, active]);
  return now;
}

/** Seconds from `now` until `iso` (negative once passed). */
export function secondsUntil(iso: string, now: number): number {
  return Math.round((Date.parse(iso) - now) / 1000);
}
