"use client";

import * as React from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import { parseAsStringLiteral, useQueryState } from "nuqs";
import {
  DataTable,
  ListWithSidebar,
  Meter,
  PageHeader,
  Segmented,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  Truncate,
  useNow,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useHasRole } from "@/lib/auth/user-context";
import type { BudgetNode } from "@/lib/api/types";
import { formatCountdown, formatNumber, formatUsd } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useDisplayNames } from "@/features/overview/api";
import { useBudgetTree, useResetBreaker } from "./api";
import {
  breakerView,
  endOfMonthLabel,
  flattenTree,
  forecastOf,
  formatAmount,
  formatWithUnit,
  hoursOf,
  isIdleSession,
  KIND_LABEL,
  limitOf,
  modelsOf,
  nameOf,
  sourceOf,
  trafficHref,
  unitOf,
  usedOf,
  type BreakerView,
  type Period,
  type TreeRow,
} from "./model";

/** HANDOFF 5.11: with no `?sel=`, the research-bot session with the open breaker is selected. */
export const DEFAULT_SELECTION = "session:s_77c1";
const PERIODS = ["today", "month"] as const;
const NO_ENDPOINT = "The admin API has no limit endpoint yet: this opens where the limit is set.";

function countdownOf(node: BudgetNode, now: number): string | null {
  const until = node.breaker?.cooldown_until;
  return until ? formatCountdown(until, now) : null;
}

const BREAKER_TEXT_CLASS: Record<BreakerView, string> = {
  open: "text-dec-block",
  half_open: "text-dec-require-approval",
  alert: "text-dec-require-approval",
  closed: "text-muted",
  none: "text-muted",
};
const BREAKER_DOT_CLASS: Record<BreakerView, string> = {
  open: "bg-dec-block",
  half_open: "bg-dec-require-approval",
  alert: "bg-dec-require-approval",
  closed: "bg-muted",
  none: "bg-muted",
};

function breakerLabel(view: BreakerView, countdown: string | null): string {
  switch (view) {
    case "open":
      return countdown ? `open · ${countdown}` : "open";
    case "half_open":
      return "half-open";
    case "alert":
      return "alert at 80%";
    case "closed":
      return "closed";
    case "none":
      return "—";
  }
}

function BreakerCell({ view, countdown }: { view: BreakerView; countdown: string | null }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[12px]", BREAKER_TEXT_CLASS[view])}>
      <span aria-hidden className={cn("size-[7px] rounded-full", BREAKER_DOT_CLASS[view])} />
      <span className={cn(view === "open" && "font-mono")}>{breakerLabel(view, countdown)}</span>
    </span>
  );
}

function limitText(node: BudgetNode, period: Period): string {
  const limit = limitOf(node, period);
  if (limit !== null) return `of ${formatAmount(limit, unitOf(node))}`;
  return node.level === "user" ? "group share" : "no own limit";
}

export function BudgetsScreen() {
  const [period, setPeriod] = useQueryState("period", parseAsStringLiteral(PERIODS).withDefault("today"));
  const [sel, setSel] = useSelectedId();
  const [closed, setClosed] = React.useState(false);
  const tree = useBudgetTree();
  const displayName = useDisplayNames();
  const [showIdle, setShowIdle] = React.useState(false);
  const allRows = React.useMemo(() => flattenTree(tree.data?.nodes ?? []), [tree.data]);
  const selectedRaw = sel ?? (closed ? null : DEFAULT_SELECTION);
  // Idle sessions (no spend, no limit, no breaker) are hidden behind a toggle; a selected one stays visible.
  const idleCount = allRows.filter((r) => isIdleSession(r.node) && r.node.id !== selectedRaw).length;
  const rows = React.useMemo(
    () => (showIdle ? allRows : allRows.filter((r) => !isIdleSession(r.node) || r.node.id === selectedRaw)),
    [allRows, showIdle, selectedRaw],
  );
  const hasOpen = rows.some((r) => r.node.breaker?.state === "open");
  const now = useNow(1000, hasOpen);

  const selectedId = selectedRaw;
  const selected = rows.find((r) => r.node.id === selectedId)?.node;
  const org = rows.find((r) => r.node.level === "org")?.node;

  const columns = React.useMemo<ColumnDef<TreeRow>[]>(
    () => [
      {
        id: "who",
        header: "Who",
        meta: { className: "max-w-[280px]" },
        cell: ({ row: { original: r } }) => (
          <span className="flex min-w-0 items-center gap-2" style={{ paddingLeft: r.depth * 18 }}>
            <span title={r.node.level === "session" ? r.node.id.slice("session:".length) : undefined} className="min-w-0">
              <Truncate className={cn(r.depth === 0 ? "font-semibold" : r.depth === 1 ? "font-medium" : "font-normal", "w-auto")}>
                {nameOf(r.node, displayName)}
              </Truncate>
            </span>
            <span className="shrink-0 text-[11px] text-muted">{KIND_LABEL[r.node.level]}</span>
          </span>
        ),
      },
      {
        id: "used",
        header: "Used of limit",
        meta: { className: "w-[220px]" },
        cell: ({ row: { original: r } }) => {
          const unit = unitOf(r.node);
          const used = usedOf(r.node, period);
          const limit = limitOf(r.node, period);
          return (
            <span className="flex flex-col gap-1">
              <span className="flex justify-between gap-2 font-mono text-[12px]">
                <span>{formatWithUnit(used, unit)}</span>
                <span className="text-muted">{limitText(r.node, period)}</span>
              </span>
              <Meter
                label={`${nameOf(r.node, displayName)}: used of limit`}
                value={used}
                max={limit ?? 0}
                danger={r.node.breaker?.state === "open"}
                className="h-[5px]"
              />
            </span>
          );
        },
      },
      {
        id: "forecast",
        header: () => <span className="block text-right">Forecast</span>,
        meta: { className: "w-[90px] text-right font-mono text-muted" },
        cell: ({ row: { original: r } }) => {
          const f = forecastOf(r.node, period);
          return f === null ? "—" : formatAmount(f, unitOf(r.node));
        },
      },
      {
        id: "breaker",
        header: "Breaker",
        meta: { className: "w-[130px]" },
        cell: ({ row: { original: r } }) => <BreakerCell view={breakerView(r.node, period)} countdown={countdownOf(r.node, now)} />,
      },
      {
        id: "go",
        header: () => <span className="sr-only">Open</span>,
        meta: { className: "w-[14px] text-muted" },
        cell: () => <span aria-hidden>›</span>,
      },
    ],
    [period, now, displayName],
  );

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader
        title="Budgets & spend"
        className="[&>div:last-child]:ml-0"
        actions={
          <Segmented
            ariaLabel="Period"
            value={period}
            onChange={(p) => void setPeriod(p)}
            options={[
              { value: "today", label: "Today" },
              { value: "month", label: "This month" },
            ]}
          />
        }
      />
      {org && <SummaryCards org={org} period={period} />}
      <ListWithSidebar
        open={!!selected}
        onClose={() => {
          setClosed(true);
          void setSel(null);
        }}
        sidebarLabel="Budget"
        list={
          <div className="flex flex-col gap-2">
          <DataTable
            ariaLabel="Budget tree"
            data={rows}
            columns={columns}
            getRowId={(r) => r.node.id}
            selectedId={selected?.id ?? null}
            onRowClick={(r) => void setSel(r.node.id)}
            keyboardNav
            minWidth={640}
            loading={tree.isPending}
            error={tree.error}
            onRetry={() => void tree.refetch()}
            emptyTitle="No budgets"
            emptyMessage="budgets.yaml defines no limits yet."
          />
          {(idleCount > 0 || showIdle) && (
            <button
              type="button"
              aria-pressed={showIdle}
              onClick={() => setShowIdle((v) => !v)}
              className="self-start text-[12.5px] text-accent hover:underline"
            >
              {showIdle ? "Hide idle sessions" : `Show ${idleCount} idle ${idleCount === 1 ? "session" : "sessions"}`}
            </button>
          )}
          </div>
        }
        sidebar={selected && <BudgetSidebar key={selected.id} node={selected} period={period} now={now} name={nameOf(selected, displayName)} />}
      />
    </div>
  );
}

/* ---------------------------------------------------------------- summary cards */

function SummaryCard({
  title,
  value,
  unit,
  bar,
  note,
}: {
  title: string;
  value: string;
  unit: string;
  bar?: React.ReactNode;
  note: string;
}) {
  return (
    <section aria-label={title} className="flex min-w-0 flex-col gap-1.5 rounded-[8px] border border-border bg-surface px-4 py-3.5">
      <span className="text-[12px] text-muted">{title}</span>
      <span className="flex items-baseline gap-2">
        <span className="font-mono text-[24px] font-semibold">{value}</span>
        <span className="text-muted">{unit}</span>
      </span>
      {bar ?? <span className="h-1.5" aria-hidden />}
      <span className="text-[12px] text-muted">{note}</span>
    </section>
  );
}

function SummaryCards({ org, period }: { org: BudgetNode; period: Period }) {
  const today = period === "today";
  const spent = usedOf(org, period, "usd");
  const limit = limitOf(org, period, "usd");
  const forecast = forecastOf(org, period, "usd");
  const gpu = usedOf(org, period, "gpu_seconds");
  const gpuLimit = limitOf(org, period, "gpu_seconds");
  const u = org.usage;
  const savedPct = typeof u["saved.pct"] === "number" ? u["saved.pct"] : null;
  const savedUsd = u[today ? "saved.usd_day" : "saved.usd_month"];
  const guardsDay = u["guards.gpu_seconds_day"];
  const guardsPct = u["guards.pct_month"];
  const specialistSaved = u["specialist.gpu_seconds_saved_month"];

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
      <SummaryCard
        title={today ? "Spent today" : "Spent this month"}
        value={formatUsd(spent)}
        unit={limit !== null ? `of ${formatUsd(limit)} USD` : "USD"}
        bar={limit !== null ? <Meter label={today ? "Spent today" : "Spent this month"} value={spent} max={limit} forecast={forecast ?? undefined} /> : undefined}
        note={forecast !== null ? `forecast ${formatUsd(forecast)} by ${today ? "midnight" : endOfMonthLabel()}` : "no forecast yet"}
      />
      <SummaryCard
        title="Local GPU time"
        value={formatNumber(gpu)}
        unit={gpuLimit !== null ? `of ${formatNumber(gpuLimit)} GPU-s` : "GPU-s"}
        bar={gpuLimit !== null ? <Meter label="Local GPU time" value={gpu} max={gpuLimit} /> : undefined}
        note={
          today
            ? typeof guardsDay === "number"
              ? `guards use ${formatNumber(guardsDay)} GPU-s of it`
              : "local models and guards"
            : typeof guardsPct === "number"
              ? `${guardsPct}% used by guards`
              : "local models and guards"
        }
      />
      <SummaryCard
        title="Saved vs sending everything to the cloud"
        value={savedPct !== null ? `${savedPct}%` : "—"}
        unit={typeof savedUsd === "number" ? `≈ ${formatUsd(savedUsd)} USD${today ? " today" : ""}` : ""}
        bar={
          savedPct !== null ? (
            <span className="h-1.5 rounded-full bg-inset" role="img" aria-label={`${savedPct}% saved`}>
              <span className="block h-1.5 rounded-full bg-dec-allow" style={{ width: `${Math.min(100, savedPct)}%` }} />
            </span>
          ) : undefined
        }
        note={
          today || typeof specialistSaved !== "number"
            ? "same tokens priced at Gemini"
            : `local/loan-memo saved ${formatNumber(specialistSaved)} GPU-s`
        }
      />
    </div>
  );
}

/* ---------------------------------------------------------------- sidebar */

function BudgetSidebar({ node, period, now, name }: { node: BudgetNode; period: Period; now: number; name: string }) {
  const isAdmin = useHasRole("admin");
  const reset = useResetBreaker();
  const unit = unitOf(node);
  const used = usedOf(node, period);
  const limit = limitOf(node, period);
  const forecast = forecastOf(node, period);
  const hours = hoursOf(node);
  const maxHour = Math.max(0, ...hours);
  const models = modelsOf(node, period);
  const source = sourceOf(node);
  const open = node.breaker?.state === "open";
  const countdown = countdownOf(node, now);
  const maxBy = { usd: Math.max(0, ...models.filter((m) => m.unit === "usd").map((m) => m.value)), gpu_seconds: Math.max(0, ...models.filter((m) => m.unit === "gpu_seconds").map((m) => m.value)) };

  return (
    <>
      <SidebarHeader label={KIND_LABEL[node.level]} title={name} />
      {node.level === "session" && (
        <div className="px-3.5 pt-2.5 text-[12px] text-muted">
          Full id <span className="break-all font-mono text-text">{node.id.slice("session:".length)}</span>
        </div>
      )}
      {open && (
        <div
          role="status"
          className="tint mx-3.5 mt-3.5 rounded-[6px] px-3 py-2.5 text-[12.5px] text-text"
          style={{ "--c": "var(--dec-block)" } as React.CSSProperties}
        >
          <b className="font-semibold text-dec-block">Breaker open.</b> {node.breaker?.reason ?? "Requests are stopped until the breaker closes."}
          {countdown && (
            <>
              {" "}
              It tries again in <span className="font-mono">{countdown}</span>.
            </>
          )}
        </div>
      )}
      <SidebarBlock>
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-mono text-[22px] font-semibold">{formatWithUnit(used, unit)}</span>
          <span className="text-muted">
            {limit !== null ? `of ${formatAmount(limit, unit)}` : node.level === "user" ? "group share" : "no own limit"} · forecast{" "}
            {forecast !== null ? formatAmount(forecast, unit) : "—"}
          </span>
        </div>
        {limit !== null && <Meter label="Used of limit" value={used} max={limit} forecast={forecast ?? undefined} danger={open} />}
        {hours.length > 0 && (
          <div className="flex flex-col gap-1">
            <div role="img" aria-label="Spend per hour today" className="flex h-[70px] items-end gap-1 border-b border-border">
              {hours.map((h, i) => (
                <span
                  key={i}
                  title={`${String(i).padStart(2, "0")}:00 · ${formatWithUnit(h, unit)}`}
                  className={cn("flex-1 rounded-t-[2px]", open && i >= hours.length - 2 ? "bg-dec-block" : "bg-accent-line")}
                  style={{ height: maxHour > 0 ? Math.max(2, Math.round((h / maxHour) * 64)) : 2 }}
                />
              ))}
            </div>
            <div className="flex justify-between font-mono text-[10.5px] text-muted" aria-hidden>
              <span>00:00</span>
              <span>{String(Math.floor(hours.length / 2)).padStart(2, "0")}:00</span>
              <span>now</span>
            </div>
          </div>
        )}
      </SidebarBlock>
      {models.length > 0 && (
        <SidebarSection title="By model" aside={period === "today" ? "today" : "this month"}>
          <ul aria-label="By model" className="m-0 flex list-none flex-col gap-1.5 p-0">
            {models.map((m) => (
              <li key={m.model} className="grid grid-cols-[minmax(0,1fr)_100px] items-center gap-2.5 text-[12.5px]">
                <span className="flex min-w-0 flex-col gap-[3px]">
                  <span className="truncate font-mono text-[12px]">{m.model}</span>
                  <span className="h-[3px] rounded-[2px] bg-inset" aria-hidden>
                    <span
                      className={cn("block h-[3px] rounded-[2px]", m.unit === "usd" ? "bg-accent" : "bg-border-strong")}
                      style={{ width: `${maxBy[m.unit] > 0 ? Math.max(2, (m.value / maxBy[m.unit]) * 100) : 0}%` }}
                    />
                  </span>
                </span>
                <span className="text-right font-mono">{formatWithUnit(m.value, m.unit)}</span>
              </li>
            ))}
          </ul>
        </SidebarSection>
      )}
      <div className="flex flex-col gap-2 px-3.5 pt-3.5">
        <span className="text-[12.5px] text-muted">
          Limit set in{" "}
          <Link href={source.href} className="font-mono text-accent">
            {source.label}
          </Link>{" "}
          · alert at 80%
        </span>
        {reset.isSuccess && (
          <StatusBox variant="success" title="Breaker closed">
            {name} can run again. The limit is unchanged; the breaker opens again if it is reached.
          </StatusBox>
        )}
        {reset.isError && (
          <StatusBox variant="error" title="Could not reset the breaker">
            {reset.error.message}
          </StatusBox>
        )}
      </div>
      <SidebarActions>
        {open && node.breaker && (
          <Button
            variant="primary"
            disabled={!isAdmin || reset.isPending}
            title={isAdmin ? undefined : "Only admins can reset a breaker"}
            onClick={() => reset.mutate(node.breaker!.id)}
          >
            {reset.isPending ? "Resetting…" : "Reset breaker"}
          </Button>
        )}
        {isAdmin ? (
          <Button asChild title={NO_ENDPOINT}>
            <Link href={source.href}>Change limit…</Link>
          </Button>
        ) : (
          <Button disabled title="Only admins can change limits">
            Change limit…
          </Button>
        )}
        <Link href={trafficHref(node)} className="self-center text-[12.5px] text-accent">
          Requests in Traffic →
        </Link>
      </SidebarActions>
    </>
  );
}

