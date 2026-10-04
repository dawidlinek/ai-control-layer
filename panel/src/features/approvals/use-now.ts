"use client";

import * as React from "react";

/** Current time, re-rendered every `intervalMs` (live countdowns). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** Seconds from `now` until `iso` (negative once passed). */
export function secondsUntil(iso: string, now: number): number {
  return Math.round((Date.parse(iso) - now) / 1000);
}
