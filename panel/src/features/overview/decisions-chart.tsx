"use client";

import * as React from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts";
import type { NameType, ValueType } from "recharts/types/component/DefaultTooltipContent";
import { DecisionBadge } from "@/components/rogatka";
import { DECISION_VAR, DECISIONS, type Decision } from "@/lib/decisions";
import { formatNumber } from "@/lib/format";
import type { DecisionBucket } from "@/lib/api/types";

/** Decisions in the order they stack (allow at the bottom, block on top) - the global decision order. */
export function decisionsIn(buckets: readonly DecisionBucket[]): Decision[] {
  return DECISIONS.filter((d) => buckets.some((b) => (b.counts[d] ?? 0) > 0));
}

function ChartTooltip({ active, payload, label }: TooltipContentProps<ValueType, NameType>) {
  if (!active || !payload?.length) return null;
  const rows = [...payload].reverse().filter((p) => Number(p.value) > 0);
  return (
    <div className="flex min-w-[150px] flex-col gap-1 rounded-[6px] border border-border-strong bg-surface px-2.5 py-2 text-[12px] shadow-[var(--shadow-pop)]">
      <span className="font-mono text-[11px] text-muted">{label}</span>
      {rows.map((p) => (
        <span key={String(p.dataKey)} className="flex items-center justify-between gap-3">
          <DecisionBadge decision={p.dataKey as Decision} />
          <span className="font-mono text-text">{formatNumber(Number(p.value))}</span>
        </span>
      ))}
    </div>
  );
}

/**
 * Stacked bars per time bucket by decision. Colours are the decision tokens (CSS variables, both themes);
 * allow is muted so the interesting decisions stand out. Identity is never colour alone: the legend chips
 * under the chart carry icon + label + total, and the tooltip lists each decision with its badge.
 */
export function DecisionsChart({
  buckets,
  labelOf,
  ariaLabel,
}: {
  buckets: readonly DecisionBucket[];
  labelOf: (iso: string) => string;
  ariaLabel: string;
}) {
  const decisions = decisionsIn(buckets);
  const data = buckets.map((b) => ({ label: labelOf(b.start), ...b.counts }));
  const ticks = data.length ? [data[0].label, data[Math.floor((data.length - 1) / 2)].label, data[data.length - 1].label] : [];

  return (
    <div className="flex flex-col gap-1">
      <div role="img" aria-label={ariaLabel} className="h-[124px] border-b border-border">
        <ResponsiveContainer width="100%" height="100%" initialDimension={{ width: 520, height: 124 }}>
          <BarChart data={data} margin={{ top: 4, right: 0, bottom: 0, left: 0 }} barCategoryGap={2}>
            <XAxis dataKey="label" hide />
            <YAxis hide />
            <Tooltip content={ChartTooltip} cursor={{ fill: "var(--raised)" }} isAnimationActive={false} />
            {decisions.map((d, i) => (
              <Bar
                key={d}
                dataKey={d}
                stackId="decisions"
                fill={DECISION_VAR[d]}
                fillOpacity={d === "allow" ? 0.38 : 1}
                stroke="var(--surface)"
                strokeWidth={1}
                radius={i === decisions.length - 1 ? [2, 2, 0, 0] : 0}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="flex justify-between font-mono text-[10.5px] text-muted" aria-hidden>
        {ticks.map((t, i) => (
          <span key={i}>{t}</span>
        ))}
      </div>
    </div>
  );
}
