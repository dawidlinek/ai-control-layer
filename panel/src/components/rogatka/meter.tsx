import * as React from "react";
import { cn } from "@/lib/utils";

export type MeterState = "normal" | "warning" | "danger";

/** `normal` below 80 %, `warning` (orange) from 80 %, `danger` (red) from 100 % or when forced (open breaker). */
export function meterState(used: number, limit: number, forceDanger = false): MeterState {
  if (forceDanger) return "danger";
  const ratio = limit > 0 ? used / limit : 0;
  return ratio >= 1 ? "danger" : ratio >= 0.8 ? "warning" : "normal";
}

const FILL: Record<MeterState, string> = {
  normal: "bg-accent",
  warning: "bg-dec-require-approval",
  danger: "bg-dec-block",
};

/**
 * Horizontal usage bar. accent normally, orange at >= 80 %, red when over the limit or `danger`.
 * `forecast` (same unit as `value` / `max`) draws a tick where usage is expected to end.
 */
export function Meter({
  value,
  max,
  forecast,
  danger = false,
  label,
  className,
}: {
  value: number;
  max: number;
  forecast?: number;
  danger?: boolean;
  /** Accessible name, e.g. "Spend today". */
  label: string;
  className?: string;
}) {
  const state = meterState(value, max, danger);
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  const tick = forecast !== undefined && max > 0 ? Math.min(100, (forecast / max) * 100) : null;
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
      data-state={state}
      className={cn("relative h-1.5 w-full rounded-full bg-inset", className)}
    >
      <div className={cn("h-full rounded-full", FILL[state])} style={{ width: `${pct}%` }} />
      {tick !== null && (
        <span
          data-forecast
          aria-hidden
          className="absolute -top-[3px] h-3 w-0.5 rounded-sm bg-muted"
          style={{ left: `calc(${tick}% - 1px)` }}
        />
      )}
    </div>
  );
}
