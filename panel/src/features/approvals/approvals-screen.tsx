"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { parseAsArrayOf, parseAsInteger, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import {
  DataTable,
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  ListWithSidebar,
  PageHeader,
  Pagination,
  SegmentedTabs,
  secondsUntil,
  Truncate,
  useNow,
  useSelectedId,
} from "@/components/rogatka";
import { DECISION_VAR } from "@/lib/decisions";
import { formatCountdown } from "@/lib/format";
import { LoadedOfTotal } from "@/lib/api/loaded-of-total";
import { cn } from "@/lib/utils";
import { useAllApprovals, usePeople } from "./api";
import { ApprovalSidebar } from "./approval-sidebar";
import { decidedRecently, toRow, type ApprovalRow } from "./model";
import { AUTO_DENY_MINUTES } from "./readers";

const TABS = ["pending", "decided", "all"] as const;
const PAGE_SIZE = 25;

/** Pending and either high risk or under 2 minutes left: highlighted in the Time left column. */
function isUrgent(r: ApprovalRow, now: number): boolean {
  return r.a.status === "pending" && (r.a.risk_score >= 0.7 || secondsUntil(r.a.expires_at, now) < 120);
}

function TimeLeft({ row }: { row: ApprovalRow }) {
  const now = useNow(1000);
  const { a } = row;
  if (a.status !== "pending") {
    const color =
      a.status === "approved" ? "text-dec-allow" : a.status === "denied" ? "text-dec-block" : "text-muted";
    return <span className={cn("px-[7px] font-mono text-[12px]", color)}>{a.status}</span>;
  }
  const urgent = isUrgent(row, now);
  return (
    <span
      data-urgent={urgent || undefined}
      className={cn("rounded-[4px] px-[7px] py-px font-mono text-[12px]", urgent ? "tint border-0" : "text-text")}
      style={urgent ? ({ "--c": DECISION_VAR.require_approval } as React.CSSProperties) : undefined}
    >
      {formatCountdown(a.expires_at, now)}
    </span>
  );
}

const columns: ColumnDef<ApprovalRow>[] = [
  {
    id: "request",
    header: "Request",
    meta: { className: "max-w-[260px]" },
    cell: ({ row: { original: r } }) => (
      <div className="flex min-w-0 flex-col gap-0.5">
        <Truncate className="font-mono text-[12px]">{r.short}</Truncate>
        <span className="font-mono text-[12px] text-muted">{r.a.id}</span>
      </div>
    ),
  },
  {
    id: "who",
    header: "Who",
    meta: { className: "w-[170px] max-w-[170px]" },
    cell: ({ row: { original: r } }) => (
      <div className="min-w-0">
        <Truncate className="font-medium">{r.who.name}</Truncate>
        <Truncate className="text-[12px] text-muted">{r.whoLine}</Truncate>
      </div>
    ),
  },
  {
    id: "why",
    header: "Why it was held",
    meta: { className: "max-w-[220px] text-muted" },
    cell: ({ row: { original: r } }) => <Truncate>{r.reasons[0]}</Truncate>,
  },
  {
    id: "approver",
    header: "Approver",
    meta: { className: "w-[120px] whitespace-nowrap" },
    cell: ({ row: { original: r } }) => r.approver,
  },
  {
    id: "left",
    header: "Time left",
    meta: { className: "w-[90px] text-right", headerClassName: "text-right" },
    cell: ({ row: { original: r } }) => <TimeLeft row={r} />,
  },
];

export function ApprovalsScreen() {
  const [sel, setSel] = useSelectedId();
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("pending"));
  const [approver, setApprover] = useQueryState("approver", parseAsArrayOf(parseAsString).withDefault([]));
  const [who, setWho] = useQueryState("who", parseAsArrayOf(parseAsString).withDefault([]));
  const [tool, setTool] = useQueryState("tool", parseAsArrayOf(parseAsString).withDefault([]));
  const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
  // Decided in this visit: they stay on the Waiting tab (the row "flips") until the tab changes.
  const [justDecided, setJustDecided] = React.useState<ReadonlySet<string>>(new Set());

  const approvals = useAllApprovals();
  const people = usePeople();
  const now = useNow(30_000);

  const all = React.useMemo(() => (approvals.data ?? []).map((a) => toRow(a, people.data)), [approvals.data, people.data]);

  // A request whose 10 minutes ran out is denied by the gateway: refetch so it leaves the Waiting tab.
  const overdue = all.some((r) => r.a.status === "pending" && Date.parse(r.a.expires_at) <= now);
  const refetch = approvals.refetch;
  React.useEffect(() => {
    if (overdue) void refetch();
  }, [overdue, refetch]);

  const counts = {
    pending: all.filter((r) => r.a.status === "pending").length,
    decided: all.filter((r) => decidedRecently(r.a, now)).length,
    // X-Total-Count: more than the loaded page when the list was cut off at the request limit.
    all: Math.max(all.length, approvals.total ?? 0),
  };

  const inTab = (r: ApprovalRow) =>
    tab === "all" ||
    (tab === "pending" ? r.a.status === "pending" || justDecided.has(r.a.id) : decidedRecently(r.a, now));

  const filtered = all.filter(
    (r) =>
      inTab(r) &&
      (approver.length === 0 || approver.includes(r.a.approver_scope)) &&
      (who.length === 0 || who.includes(r.a.requested_by)) &&
      (tool.length === 0 || tool.includes(r.a.tool ?? "")),
  );
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pageCount);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const selected = rows.find((r) => r.a.id === sel);

  const uniq = <T,>(xs: T[]) => [...new Set(xs)];
  const whoOptions = uniq(all.map((r) => r.a.requested_by)).map((u) => ({
    value: u,
    label: all.find((r) => r.a.requested_by === u)?.who.name ?? u,
  }));
  const toolOptions = uniq(all.map((r) => r.a.tool).filter((t): t is string => !!t)).map((t) => ({ value: t, label: t }));

  const filterChange = (set: (v: string[]) => unknown) => (v: string[]) => {
    void set(v);
    void setPage(1);
  };

  return (
    <>
      <PageHeader title="Approvals" />
      <FilterRow>
        <SegmentedTabs
          ariaLabel="Status"
          value={tab}
          onChange={(v) => {
            setJustDecided(new Set());
            void setTab(v);
            void setPage(1);
          }}
          tabs={[
            { value: "pending", label: "Waiting", count: approvals.data ? counts.pending : undefined },
            { value: "decided", label: "Decided · 24 h", count: approvals.data ? counts.decided : undefined },
            { value: "all", label: "All", count: approvals.data ? counts.all : undefined },
          ]}
        />
        <FilterMenuButton
          label="Approver"
          options={[
            { value: "admin", label: "Security team" },
            { value: "user", label: "Team lead" },
          ]}
          selected={approver}
          onChange={filterChange(setApprover)}
        />
        <FilterMenuButton label="Who" options={whoOptions} selected={who} onChange={filterChange(setWho)} />
        <FilterMenuButton label="Tool" options={toolOptions} selected={tool} onChange={filterChange(setTool)} />
        <FilterSpacer />
        <span className="text-[12px] text-muted">Requests nobody answers are denied after {AUTO_DENY_MINUTES} minutes</span>
      </FilterRow>
      <ListWithSidebar
        open={!!selected}
        onClose={() => void setSel(null)}
        sidebarLabel="Approval request"
        list={
          <>
            <DataTable
              ariaLabel="Approval requests"
              data={rows}
              columns={columns}
              getRowId={(r) => r.a.id}
              selectedId={sel}
              onRowClick={(r) => void setSel(r.a.id)}
              keyboardNav
              minWidth={700}
              loading={approvals.isPending}
              error={approvals.error}
              onRetry={() => void approvals.refetch()}
              emptyTitle={tab === "pending" ? "Nothing is waiting" : "No requests"}
              emptyMessage={tab === "pending" ? "Held actions show up here for a person to decide." : undefined}
            />
            <Pagination page={current} pageCount={pageCount} pageSize={PAGE_SIZE} onPageChange={(p) => void setPage(p)} />
            <LoadedOfTotal loaded={all.length} total={approvals.total} noun="requests" />
          </>
        }
        sidebar={
          selected && (
            <ApprovalSidebar
              key={selected.a.id}
              row={selected}
              onDecided={(id) => setJustDecided((s) => new Set(s).add(id))}
            />
          )
        }
      />
    </>
  );
}
