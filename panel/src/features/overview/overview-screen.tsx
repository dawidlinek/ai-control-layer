"use client";

import * as React from "react";
import Link from "next/link";
import { parseAsStringLiteral, useQueryState } from "nuqs";
import { Card, DecisionBadge, DecisionChips, ErrorState, LoadingRows, Meter, PageHeader, PathIcon, Segmented } from "@/components/rogatka";
import { useIncidents } from "@/lib/api/hooks";
import type { EventSummary, ModelCost, OverviewSummary } from "@/lib/api/types";
import { DECISIONS, SEVERITIES, SEVERITY_ICON, SEVERITY_VAR, toSeverity, type Decision, type Severity } from "@/lib/decisions";
import { formatClock, formatNumber, formatTime, formatUsd } from "@/lib/format";
import { cn } from "@/lib/utils";
import { RANGES, useDisplayNames, useOverview, useRecentDecisions, type Range } from "./api";
import { DecisionsChart } from "./decisions-chart";
import { topRisks } from "./risks";

const RANGE_TEXT: Record<Range, string> = { "15m": "last 15 min", "1h": "last hour", "24h": "last 24 h", "7d": "last 7 days" };
const BUCKET_TEXT: Record<Range, string> = { "15m": "minute", "1h": "5 minutes", "24h": "hour", "7d": "day" };
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** Notes next to model ids in the cost table (HANDOFF 7.1 lineup). */
const MODEL_NOTE: Record<string, string> = {
  "gemini/flash": "fast",
  "gemini/pro": "strong",
  "local/qwen3.8-27b": "incl. judge",
  "local/loan-memo": "specialist",
  guards: "classifier + NER",
};

const linkCls = "text-[12.5px] text-accent no-underline hover:underline";

/** `318k`, `1.4M`, `412`. */
export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

export function OverviewScreen() {
  const [range, setRange] = useQueryState("range", parseAsStringLiteral(RANGES).withDefault("15m"));
  const summary = useOverview(range);
  const day = useOverview("24h");

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Overview"
        // The range switch sits right next to the title, as in the prototype (not pushed to the right edge).
        className="[&>div:last-child]:ml-0"
        actions={
          <Segmented
            ariaLabel="Time range"
            size="sm"
            value={range}
            onChange={(r) => void setRange(r)}
            options={RANGES.map((r) => ({ value: r, label: r }))}
          />
        }
      />
      <div className="flex flex-wrap items-stretch gap-4">
        <HappeningCard range={range} summary={summary.data} loading={summary.isPending} error={summary.error} onRetry={() => void summary.refetch()} />
        <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-4">
          <SafeCard day={day.data} loading={day.isPending} error={day.error} onRetry={() => void day.refetch()} />
          <CostCard summary={day.data} loading={day.isPending} error={day.error} onRetry={() => void day.refetch()} />
        </div>
      </div>
    </div>
  );
}

interface CardProps {
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}

function CardBody({ loading, error, onRetry, children }: CardProps & { children: () => React.ReactNode }) {
  if (loading) return <LoadingRows rows={4} />;
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  return <>{children()}</>;
}

/* ---------------------------------------------------------------- What is happening? */

function bucketLabel(range: Range) {
  return (iso: string) => {
    const d = new Date(iso);
    return range === "7d" ? `${DAYS[d.getDay()]} ${d.getDate()}` : formatClock(d);
  };
}

function HappeningCard({ range, summary, ...state }: CardProps & { range: Range; summary?: OverviewSummary }) {
  const recent = useRecentDecisions();
  const nameOf = useDisplayNames();
  const notable = (recent.data ?? []).filter((e) => e.action && e.action !== "allow").slice(0, 5);

  return (
    <Card title="What is happening?" className="flex-[1_1_520px]">
      <CardBody {...state}>
        {() => {
          const s = summary!;
          const legend = DECISIONS.filter((d) => (s.decisions_by_action[d] ?? 0) > 0);
          return (
            <>
              <div className="flex items-baseline gap-2.5">
                <span className="font-mono text-[34px] font-semibold tracking-[-0.02em]">{formatNumber(s.decisions_total)}</span>
                <span className="text-muted">decisions · {RANGE_TEXT[range]}</span>
              </div>
              <DecisionsChart
                buckets={s.timeline}
                labelOf={bucketLabel(range)}
                ariaLabel={`Decisions per ${BUCKET_TEXT[range]}, stacked by decision`}
              />
              <ul aria-label="Decisions by type" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
                {legend.map((d) => (
                  <li key={d}>
                    <Link href={`/traffic?decision=${d}`} className="no-underline" aria-label={`${d} ${s.decisions_by_action[d]}`}>
                      <DecisionBadge decision={d} size="lg">
                        <span className="ml-1 text-text">{formatNumber(s.decisions_by_action[d])}</span>
                      </DecisionBadge>
                    </Link>
                  </li>
                ))}
              </ul>
            </>
          );
        }}
      </CardBody>
      <div className="flex flex-col gap-0.5 border-t border-border pt-3">
        <div className="mb-1 text-[12px] text-muted">Notable now</div>
        {recent.isPending && <LoadingRows rows={3} />}
        {recent.error && <ErrorState error={recent.error} onRetry={() => void recent.refetch()} />}
        {recent.data && notable.length === 0 && <p className="m-0 text-muted">Nothing but allowed requests lately.</p>}
        <ul aria-label="Notable now" className="m-0 flex list-none flex-col p-0">
          {notable.map((e) => (
            <li key={e.event_id}>
              <NotableRow event={e} who={e.agent_id ?? nameOf(e.username)} />
            </li>
          ))}
        </ul>
        <Link href="/traffic" className={cn(linkCls, "mt-1.5")}>
          Open traffic →
        </Link>
      </div>
    </Card>
  );
}

function NotableRow({ event, who }: { event: EventSummary; who: string }) {
  const decisions: Decision[] = event.applied.length ? event.applied : event.action ? [event.action] : [];
  return (
    <Link
      href={`/traffic?sel=${encodeURIComponent(event.trace_id ?? event.event_id)}`}
      className="-mx-1.5 grid grid-cols-[58px_minmax(0,1fr)] gap-x-2.5 gap-y-1 rounded-[6px] px-1.5 py-1.5 text-text no-underline hover:bg-raised"
    >
      <span className="pt-px font-mono text-[11.5px] text-muted">{formatTime(event.timestamp)}</span>
      <span className="flex min-w-0 flex-col gap-1">
        <span className="line-clamp-2">
          <b className="font-semibold">{who}</b> <span className="text-muted">— {event.summary || `${event.point ?? "request"}: ${event.action}`}</span>
        </span>
        <DecisionChips decisions={decisions} />
      </span>
    </Link>
  );
}

/* ---------------------------------------------------------------- Are we safe? */

function SafeCard({ day, ...state }: CardProps & { day?: OverviewSummary }) {
  const incidents = useIncidents();
  const open = (incidents.data ?? []).filter((i) => i.status === "open" || i.status === "triaged");
  const bySeverity = new Map<Severity, number>();
  for (const i of open) bySeverity.set(toSeverity(i.severity), (bySeverity.get(toSeverity(i.severity)) ?? 0) + 1);

  return (
    <Card title="Are we safe?">
      {incidents.isPending ? (
        <LoadingRows rows={1} />
      ) : incidents.error ? (
        <ErrorState error={incidents.error} onRetry={() => void incidents.refetch()} />
      ) : (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Link href="/incidents" className="flex items-baseline gap-2 text-text no-underline hover:underline">
            <span className="font-mono text-[28px] font-semibold tracking-[-0.02em]">{open.length}</span>
            <span className="text-muted">open {open.length === 1 ? "incident" : "incidents"}</span>
          </Link>
          <span className="flex flex-wrap gap-1.5">
            {SEVERITIES.filter((s) => bySeverity.has(s)).map((s) => (
              <Link
                key={s}
                href={`/incidents?severity=${s}`}
                data-severity={s}
                className="tint inline-flex items-center gap-[5px] rounded-[5px] py-px pl-1.5 pr-2 text-[12px] no-underline"
                style={{ "--c": SEVERITY_VAR[s] } as React.CSSProperties}
              >
                <PathIcon path={SEVERITY_ICON[s]} size={13} strokeWidth={2.2} />
                <span className="font-mono font-semibold">{bySeverity.get(s)}</span> {s}
              </Link>
            ))}
          </span>
        </div>
      )}
      <div className="flex flex-col gap-1.5 border-t border-border pt-3">
        <div className="flex justify-between text-[12px] text-muted">
          <span>Top risks · 24 h</span>
          <span>OWASP</span>
        </div>
        <CardBody {...state}>
          {() => {
            const risks = topRisks(day!.top_taxonomy, 5);
            const max = Math.max(1, ...risks.map((r) => r.count));
            return (
              <ul aria-label="Top risks" className="m-0 flex list-none flex-col gap-1.5 p-0">
                {risks.map(({ id, name, count: n }) => (
                  <li key={id}>
                    <Link
                      href={`/traffic?q=${encodeURIComponent(id)}`}
                      className="grid grid-cols-[46px_minmax(0,1fr)_36px] items-center gap-2 text-[12px] text-text no-underline hover:bg-raised"
                    >
                      <span className="truncate font-mono text-muted" title={id}>
                        {id}
                      </span>
                      <span className="flex min-w-0 flex-col gap-[3px]">
                        {name !== id && <span className="truncate">{name}</span>}
                        <span className="h-[3px] rounded-[2px] bg-inset">
                          <span className="block h-[3px] rounded-[2px] bg-accent-line" style={{ width: `${Math.max(1, (n / max) * 100)}%` }} />
                        </span>
                      </span>
                      <span className="text-right font-mono">{formatNumber(n)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            );
          }}
        </CardBody>
      </div>
    </Card>
  );
}

/* ---------------------------------------------------------------- What is it costing? */

function usageText(m: ModelCost): string {
  return m.tier === "cloud" ? `${formatUsd(m.usd)} USD` : `${formatNumber(m.gpu_seconds)} GPU-s`;
}

function CostCard({ summary, ...state }: CardProps & { summary?: OverviewSummary }) {
  return (
    <Card title="What is it costing?">
      <CardBody {...state}>
        {() => {
          const s = summary!;
          const limit = s.usd_limit_day;
          const pct = limit ? Math.round((s.usd_today / limit) * 100) : null;
          const gpuLimit = s.gpu_seconds_limit_day;
          const gpuPct = gpuLimit ? Math.round((s.gpu_seconds_today / gpuLimit) * 100) : null;
          const maxShare = Math.max(0.0001, ...s.cost_by_model.map((m) => m.share));
          return (
            <>
              <div className="flex flex-wrap gap-x-7 gap-y-3.5">
                <div className="flex min-w-0 flex-[1.3_1_240px] flex-col gap-1.5">
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-[28px] font-semibold tracking-[-0.02em]">{formatUsd(s.usd_today)}</span>
                    <span className="text-muted">{limit ? `/ ${formatUsd(limit)} USD today` : "USD today"}</span>
                  </div>
                  {limit ? (
                    <Meter label="Spend today" value={s.usd_today} max={limit} forecast={s.usd_forecast_day ?? undefined} className="h-2" />
                  ) : null}
                  <div className="flex justify-between text-[12px] text-muted">
                    <span>{pct !== null ? `${pct}% used` : "no daily limit"}</span>
                    {s.usd_forecast_day !== null && <span>forecast {formatUsd(s.usd_forecast_day)} by 24:00</span>}
                  </div>
                </div>
                <div className="flex min-w-0 flex-[1_1_180px] flex-col justify-end gap-1.5">
                  <div className="flex justify-between text-[12px]">
                    <span className="text-muted">GPU-seconds</span>
                    <span className="font-mono">
                      {formatNumber(s.gpu_seconds_today)}
                      {gpuLimit ? ` / ${formatNumber(gpuLimit)}` : ""}
                    </span>
                  </div>
                  {gpuLimit ? <Meter label="GPU-seconds today" value={s.gpu_seconds_today} max={gpuLimit} /> : null}
                  <div className="text-[12px] text-muted">{gpuPct !== null ? `${gpuPct}% used` : "no daily limit"}</div>
                </div>
              </div>
              <table aria-label="Usage by model today" className="w-full border-collapse border-t border-border text-[12px]">
                <thead>
                  <tr className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-muted">
                    <th scope="col" className="border-b border-border py-1 text-left font-semibold">Model · today</th>
                    <th scope="col" className="w-32 border-b border-border py-1 text-right font-semibold">Tokens in / out</th>
                    <th scope="col" className="w-24 border-b border-border py-1 text-right font-semibold">Usage</th>
                  </tr>
                </thead>
                <tbody>
                  {s.cost_by_model.map((m) => (
                    <tr key={m.model}>
                      <td className="max-w-0 border-b border-border py-1.5 pr-3">
                        <span className="flex min-w-0 flex-col gap-1">
                          <span className="truncate font-mono">
                            {m.model} {MODEL_NOTE[m.model] && <span className="text-muted">{MODEL_NOTE[m.model]}</span>}
                          </span>
                          <span className="h-[3px] rounded-[2px] bg-inset" aria-hidden>
                            <span
                              className={cn("block h-[3px] rounded-[2px]", m.tier === "cloud" ? "bg-accent" : "bg-border-strong")}
                              style={{ width: `${Math.max(2, (m.share / maxShare) * 100)}%` }}
                            />
                          </span>
                        </span>
                      </td>
                      <td className="border-b border-border py-1.5 text-right font-mono text-muted">
                        {formatTokens(m.tokens_in)} / {formatTokens(m.tokens_out)}
                      </td>
                      <td className="border-b border-border py-1.5 text-right font-mono font-semibold">{usageText(m)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          );
        }}
      </CardBody>
      <Link href="/budgets" className={linkCls}>
        Open budgets →
      </Link>
    </Card>
  );
}
