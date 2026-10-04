"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { ICON_PATHS, PathIcon } from "./icon";

export interface TimelineStep {
  id: string;
  /** Step name ("Rules"). */
  name: string;
  /** One-line result ("found a PESEL and an IBAN, both valid"). */
  result: React.ReactNode;
  /** Right-aligned mono duration ("7 ms"). */
  meta?: string;
  /** Steps that changed something are bold (the rings and dots are the brand motif, not a decision colour). */
  changed?: boolean;
  /** Expandable detail (the controls that ran). Steps without detail are not clickable. */
  detail?: React.ReactNode;
}

/**
 * Vertical timeline, e.g. the trace "How the decision was made". Click a step with `detail` to expand it.
 * `openId` / `onOpenChange` make expansion controllable; uncontrolled by default.
 */
export function StepTimeline({
  steps,
  defaultOpenId = null,
  openId,
  onOpenChange,
  ariaLabel = "Steps",
  className,
}: {
  steps: readonly TimelineStep[];
  defaultOpenId?: string | null;
  openId?: string | null;
  onOpenChange?: (id: string | null) => void;
  ariaLabel?: string;
  className?: string;
}) {
  const [inner, setInner] = React.useState<string | null>(defaultOpenId);
  const open = openId !== undefined ? openId : inner;
  const setOpen = (id: string | null) => {
    if (openId === undefined) setInner(id);
    onOpenChange?.(id);
  };
  return (
    <ol aria-label={ariaLabel} className={cn("m-0 flex list-none flex-col p-0", className)}>
      {steps.map((s, i) => {
        const expandable = s.detail != null;
        const expanded = expandable && open === s.id;
        const last = i === steps.length - 1;
        return (
          <li key={s.id} data-step={s.id} data-changed={s.changed || undefined} className="grid grid-cols-[20px_minmax(0,1fr)] gap-x-2.5">
            <span className="flex flex-col items-center" aria-hidden>
              {/* brand motif: 2 px accent rail, 12 px hollow ring per step, 14 px filled dot for the final step */}
              <span
                data-slot={last ? "timeline-final" : "timeline-ring"}
                className={cn(
                  "shrink-0 rounded-full border-2 border-accent",
                  last ? "mt-2 size-3.5 bg-accent" : "mt-[9px] size-3 bg-surface",
                )}
              />
              <span className={cn("w-0.5 flex-1", last ? "bg-transparent" : "bg-accent")} />
            </span>
            <div className="flex flex-col gap-1.5 pb-[7px] pt-[5px]">
              <button
                type="button"
                disabled={!expandable}
                aria-expanded={expandable ? expanded : undefined}
                onClick={() => setOpen(expanded ? null : s.id)}
                className={cn(
                  "grid grid-cols-[86px_minmax(0,1fr)_54px_14px] items-baseline gap-2 border-0 bg-transparent p-0 py-0.5 text-left text-[12.5px] text-text disabled:cursor-default",
                  expandable ? "cursor-pointer" : "cursor-default",
                )}
              >
                <b className={cn(s.changed ? "font-semibold text-text" : "font-medium text-muted")}>{s.name}</b>
                <span className={cn("min-w-0", s.changed ? "text-text" : "text-muted")}>{s.result}</span>
                <span className="text-right font-mono text-[11.5px] text-muted">{s.meta}</span>
                <span className="text-muted">
                  {expandable && <PathIcon path={expanded ? ICON_PATHS.chevronUp : ICON_PATHS.chevronDown} size={11} strokeWidth={2.4} />}
                </span>
              </button>
              {expanded && <div className="flex flex-col rounded-[6px] border border-border bg-inset">{s.detail}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
