"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { debounce, parseAsArrayOf, parseAsBoolean, parseAsInteger, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import {
  DataTable,
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  LabeledSwitch,
  ListWithSidebar,
  PageHeader,
  Pagination,
  RelativeTime,
  SearchInput,
  SegmentedTabs,
  SeverityChip,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { useUser } from "@/lib/auth/user-context";
import { SEVERITIES } from "@/lib/decisions";
import type { Incident } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { useAllIncidents } from "./api";
import { IncidentSidebar, statusClass } from "./incident-sidebar";
import { STATUS_LABEL, isClosed, summaryOf, typeLabel } from "./readers";

const TABS = ["open", "resolved", "all"] as const;
const PAGE_SIZE = 25;
const UNASSIGNED = "unassigned";
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function useColumns(me: string): ColumnDef<Incident>[] {
  return React.useMemo(
    () => [
      {
        id: "severity",
        header: "Severity",
        meta: { className: "w-[92px]" },
        cell: ({ row: { original: i } }) => <SeverityChip severity={i.severity} size="md" />,
      },
      {
        id: "incident",
        header: "Incident",
        meta: { className: "max-w-[420px]" },
        cell: ({ row: { original: i } }) => (
          <div className="flex min-w-0 flex-col gap-px">
            <Truncate className="font-medium">{i.title}</Truncate>
            <Truncate className="text-[12px] text-muted">
              <span className="font-mono">{i.id}</span> · {typeLabel(i)}
              {i.subject ? ` · ${i.subject}` : ""}
            </Truncate>
          </div>
        ),
      },
      {
        id: "status",
        header: "Status",
        meta: { className: "w-[100px]" },
        cell: ({ row: { original: i } }) => (
          <span className={cn("whitespace-nowrap rounded-[10px] border px-2 py-px text-[12px]", statusClass(i.status))}>
            {STATUS_LABEL[i.status]}
          </span>
        ),
      },
      {
        id: "assignee",
        header: "Assignee",
        meta: { className: "w-[130px] max-w-[130px]" },
        cell: ({ row: { original: i } }) =>
          i.assignee ? (
            <Truncate>
              {i.assignee}
              {i.assignee === me && " (you)"}
            </Truncate>
          ) : (
            <span className="text-muted">unassigned</span>
          ),
      },
      {
        id: "opened",
        header: "Opened",
        meta: { className: "w-[70px] text-right text-muted", headerClassName: "text-right" },
        cell: ({ row: { original: i } }) => <RelativeTime iso={i.created_at} />,
      },
    ],
    [me],
  );
}

export function IncidentsScreen() {
  const me = useUser().username;
  const [sel, setSel] = useSelectedId();
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("open"));
  const [severity, setSeverity] = useQueryState("severity", parseAsArrayOf(parseAsString).withDefault([]));
  const [type, setType] = useQueryState("type", parseAsArrayOf(parseAsString).withDefault([]));
  const [assignee, setAssignee] = useQueryState("assignee", parseAsArrayOf(parseAsString).withDefault([]));
  const [q, setQ] = useQueryState("q", parseAsString.withDefault("").withOptions({ limitUrlUpdates: debounce(300) }));
  const [mine, setMine] = useQueryState("mine", parseAsBoolean.withDefault(false));
  const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
  // Changed in this visit (resolved, reopened...): they stay in the current tab until the tab changes.
  const [touched, setTouched] = React.useState<ReadonlySet<string>>(new Set());

  const incidents = useAllIncidents();
  const columns = useColumns(me);
  const all = React.useMemo(
    () =>
      [...(incidents.data ?? [])].sort(
        (a, b) =>
          Number(isClosed(a.status)) - Number(isClosed(b.status)) ||
          (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) ||
          b.created_at.localeCompare(a.created_at),
      ),
    [incidents.data],
  );

  const counts = {
    open: all.filter((i) => !isClosed(i.status)).length,
    resolved: all.filter((i) => isClosed(i.status)).length,
    all: all.length,
  };

  const needle = q.trim().toLowerCase();
  const filtered = all.filter((i) => {
    const inTab = tab === "all" || touched.has(i.id) || (tab === "open") === !isClosed(i.status);
    if (!inTab) return false;
    if (severity.length > 0 && !severity.includes(i.severity === "info" ? "low" : i.severity)) return false;
    if (type.length > 0 && !type.includes(typeLabel(i))) return false;
    if (assignee.length > 0 && !assignee.includes(i.assignee ?? UNASSIGNED)) return false;
    if (mine && i.assignee !== me) return false;
    if (needle) {
      const hay = [i.id, i.title, i.subject ?? "", i.assignee ?? "", typeLabel(i), summaryOf(i)].join(" ").toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pageCount);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const selected = rows.find((i) => i.id === sel);

  const typeOptions = [...new Set(all.map(typeLabel))].sort().map((t) => ({ value: t, label: t }));
  const assigneeOptions = [
    { value: UNASSIGNED, label: "unassigned" },
    ...[...new Set(all.map((i) => i.assignee).filter((a): a is string => !!a))]
      .sort()
      .map((a) => ({ value: a, label: a === me ? `${a} (you)` : a })),
  ];

  const resetPage = () => void setPage(1);
  const onFilter = (set: (v: string[]) => unknown) => (v: string[]) => {
    void set(v);
    resetPage();
  };

  return (
    <>
      <PageHeader title="Incidents" />
      <FilterRow>
        <SegmentedTabsWithCounts
          tab={tab}
          loaded={!!incidents.data}
          counts={counts}
          onChange={(v) => {
            setTouched(new Set());
            void setTab(v);
            resetPage();
          }}
        />
        <FilterMenuButton
          label="Severity"
          options={SEVERITIES.map((s) => ({ value: s, label: s }))}
          selected={severity}
          onChange={onFilter(setSeverity)}
        />
        <FilterMenuButton label="Type" options={typeOptions} selected={type} onChange={onFilter(setType)} />
        <FilterMenuButton label="Assignee" options={assigneeOptions} selected={assignee} onChange={onFilter(setAssignee)} />
        <SearchInput
          value={q}
          onChange={(v) => {
            void setQ(v);
            resetPage();
          }}
          placeholder="ID, user or text"
          ariaLabel="Search incidents"
        />
        <FilterSpacer />
        <LabeledSwitch
          label="Assigned to me"
          checked={mine}
          onCheckedChange={(v) => {
            void setMine(v || null);
            resetPage();
          }}
        />
      </FilterRow>
      <ListWithSidebar
        open={!!selected}
        onClose={() => void setSel(null)}
        sidebarLabel="Incident"
        list={
          <>
            <DataTable
              ariaLabel="Incidents"
              data={rows}
              columns={columns}
              getRowId={(i) => i.id}
              selectedId={sel}
              onRowClick={(i) => void setSel(i.id)}
              keyboardNav
              minWidth={700}
              loading={incidents.isPending}
              error={incidents.error}
              onRetry={() => void incidents.refetch()}
              emptyTitle={mine ? "Nothing assigned to you here." : "No incidents"}
              emptyMessage={mine ? undefined : "Nothing matches these filters."}
            />
            <Pagination page={current} pageCount={pageCount} pageSize={PAGE_SIZE} onPageChange={(p) => void setPage(p)} />
          </>
        }
        sidebar={
          selected && (
            <IncidentSidebar
              key={selected.id}
              incident={selected}
              onChanged={(id) => setTouched((s) => new Set(s).add(id))}
            />
          )
        }
      />
    </>
  );
}

function SegmentedTabsWithCounts({
  tab,
  loaded,
  counts,
  onChange,
}: {
  tab: (typeof TABS)[number];
  loaded: boolean;
  counts: Record<(typeof TABS)[number], number>;
  onChange: (v: (typeof TABS)[number]) => void;
}) {
  return (
    <SegmentedTabs
      ariaLabel="Status"
      value={tab}
      onChange={onChange}
      tabs={[
        { value: "open", label: "Open", count: loaded ? counts.open : undefined },
        { value: "resolved", label: "Resolved", count: loaded ? counts.resolved : undefined },
        { value: "all", label: "All", count: loaded ? counts.all : undefined },
      ]}
    />
  );
}
