"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import {
  parseAsArrayOf,
  parseAsBoolean,
  parseAsInteger,
  parseAsString,
  parseAsStringLiteral,
  useQueryStates,
} from "nuqs";
import {
  DataTable,
  DecisionBadge,
  DecisionChips,
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  ICON_PATHS,
  LabeledSwitch,
  ListWithSidebar,
  PageHeader,
  Pagination,
  SearchInput,
  TimeCell,
  Truncate,
} from "@/components/rogatka";
import type { EventSummary } from "@/lib/api/types";
import { DECISIONS } from "@/lib/decisions";
import { usePeople, useTrafficPage, useTrafficStream } from "./api";
import {
  clientLine,
  DATA_CLASSES,
  decisionsOf,
  GROUPS,
  isSensitiveLabel,
  modelOrTool,
  pointLabel,
  POINTS,
  RANGE_LABEL,
  RANGES,
  whoName,
  type NameOf,
  type TrafficFilters,
} from "./model";
import { MoreFiltersButton } from "./more-filters";
import { SessionLabelChip } from "./parts";
import { TraceSidebar } from "./trace-sidebar";

const PAGE_SIZES = [25, 50, 100] as const;

const urlState = {
  range: parseAsStringLiteral(RANGES).withDefault("24h"),
  decision: parseAsArrayOf(parseAsStringLiteral(DECISIONS)).withDefault([]),
  who: parseAsString,
  point: parseAsArrayOf(parseAsStringLiteral(POINTS)).withDefault([]),
  group: parseAsString,
  class: parseAsArrayOf(parseAsStringLiteral(DATA_CLASSES)).withDefault([]),
  q: parseAsString.withDefault(""),
  hide: parseAsBoolean.withDefault(false),
  page: parseAsInteger.withDefault(1),
  size: parseAsInteger.withDefault(25),
  sel: parseAsString,
};

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const id = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(id);
  }, [value, ms]);
  return v;
}

function columns(nameOf: NameOf): ColumnDef<EventSummary>[] {
  return [
    {
      id: "time",
      header: "Time",
      cell: ({ row }) => <TimeCell iso={row.original.timestamp} />,
      meta: { className: "w-[80px]" },
    },
    {
      id: "who",
      header: "Who",
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[170px]">
          <Truncate className="font-medium">{whoName(row.original, nameOf)}</Truncate>
          <Truncate className="text-[12px] text-muted">{clientLine(row.original)}</Truncate>
        </div>
      ),
      meta: { className: "w-[170px]" },
    },
    {
      id: "point",
      header: "Point",
      cell: ({ row }) => <span className="whitespace-nowrap text-muted">{pointLabel(row.original.point)}</span>,
      meta: { className: "w-[84px]" },
    },
    {
      id: "model",
      header: "Model / tool",
      cell: ({ row }) => {
        const label = modelOrTool(row.original);
        return (
          <span title={label} className="block max-w-full truncate font-mono text-[12px]">
            {label}
          </span>
        );
      },
      meta: { className: "max-w-[260px]" },
    },
    {
      id: "decision",
      header: "Decision",
      cell: ({ row }) => {
        const label = row.original.session_label;
        return (
          <span className="flex flex-wrap gap-1">
            <DecisionChips decisions={decisionsOf(row.original)} />
            {isSensitiveLabel(label) && <SessionLabelChip label={label} />}
          </span>
        );
      },
      meta: { className: "w-[170px]" },
    },
    {
      id: "rule",
      header: "Rule",
      cell: ({ row }) => {
        const [first, ...rest] = row.original.rule_ids;
        return (
          <Truncate className="font-mono text-[12px] text-muted">
            {first ?? "—"}
            {rest.length ? ` +${rest.length}` : ""}
          </Truncate>
        );
      },
      meta: { className: "max-w-[130px]" },
    },
    {
      id: "open",
      header: () => <span className="sr-only">Open</span>,
      cell: () => (
        <span aria-hidden className="text-muted">
          ›
        </span>
      ),
      meta: { className: "w-5" },
    },
  ];
}

/** Traffic: paged list of past requests and tool calls; a row opens the trace sidebar (`?sel=`). */
export function TrafficScreen() {
  const [s, setS] = useQueryStates(urlState);
  const people = usePeople();
  const q = useDebounced(s.q, 250);
  const filters: TrafficFilters = React.useMemo(
    () => ({ range: s.range, decision: s.decision, who: s.who, point: s.point, group: s.group, dataClass: s.class, q, hideAllowed: s.hide }),
    [s.range, s.decision, s.who, s.point, s.group, s.class, q, s.hide],
  );
  const size = (PAGE_SIZES as readonly number[]).includes(s.size) ? s.size : 25;

  // Cursor per page for the current filters: page 1 starts at the newest event, page N+1 before the last row of N.
  const signature = JSON.stringify([filters, size]);
  const [cursors, setCursors] = React.useState<{ sig: string; map: Record<number, number | null> }>({ sig: signature, map: { 1: null } });
  const map = cursors.sig === signature ? cursors.map : { 1: null };
  const known = s.page in map;
  const page = known ? s.page : 1;
  const cursor = map[page] ?? null;

  const list = useTrafficPage(filters, size, cursor, people);
  useTrafficStream(filters, size, page, people);

  // A deep link to a page whose cursor is unknown starts over at page 1.
  React.useEffect(() => {
    if (!known) void setS({ page: null });
  }, [known, setS]);

  const data = list.data;
  React.useEffect(() => {
    if (!data || list.isPlaceholderData || data.nextCursor == null) return;
    setCursors((c) => {
      const base = c.sig === signature ? c.map : { 1: null };
      return base[page + 1] === data.nextCursor ? c : { sig: signature, map: { ...base, [page + 1]: data.nextCursor } };
    });
  }, [data, list.isPlaceholderData, signature, page]);

  const rows = React.useMemo(() => data?.rows ?? [], [data]);
  const selected = s.sel ? (rows.find((e) => e.event_id === s.sel) ?? rows.find((e) => e.trace_id === s.sel)) : undefined;
  const cols = React.useMemo(() => columns(people.nameOf), [people.nameOf]);

  /** Change filters: back to page 1 and close the sidebar (the selection may no longer be in the list). */
  const setFilter = (patch: Partial<Parameters<typeof setS>[0] & object>) => void setS({ ...patch, page: null, sel: null });

  const selectRow = (e: EventSummary) => {
    const sharedTrace = e.trace_id && rows.filter((r) => r.trace_id === e.trace_id).length > 1;
    void setS({ sel: e.trace_id && !sharedTrace ? e.trace_id : e.event_id });
  };
  const close = React.useCallback(() => void setS({ sel: null }), [setS]);

  return (
    <>
      <PageHeader title="Traffic" />
      <FilterRow>
        <FilterMenuButton
          label={RANGE_LABEL[s.range]}
          icon={ICON_PATHS.calendar}
          multiple={false}
          options={RANGES.map((r) => ({ value: r, label: RANGE_LABEL[r] }))}
          selected={[s.range]}
          onChange={(v) => setFilter({ range: (v[0] as (typeof RANGES)[number] | undefined) ?? s.range })}
        />
        <FilterMenuButton
          label="Decision"
          options={DECISIONS.map((d) => ({ value: d, label: <DecisionBadge decision={d} /> }))}
          selected={s.decision}
          onChange={(v) => setFilter({ decision: v.length ? (v as typeof s.decision) : null })}
        />
        <FilterMenuButton
          label="Who"
          multiple={false}
          options={people.options}
          selected={s.who ? [s.who] : []}
          onChange={(v) => setFilter({ who: v[0] ?? null })}
        />
        <FilterMenuButton
          label="Point"
          options={POINTS.map((p) => ({ value: p, label: pointLabel(p) }))}
          selected={s.point}
          onChange={(v) => setFilter({ point: v.length ? (v as typeof s.point) : null })}
        />
        <MoreFiltersButton
          groups={GROUPS}
          group={s.group}
          onGroupChange={(g) => setFilter({ group: g })}
          dataClasses={DATA_CLASSES}
          dataClass={s.class}
          onDataClassChange={(c) => setFilter({ class: c.length ? (c as typeof s.class) : null })}
        />
        <SearchInput
          value={s.q}
          onChange={(v) => setFilter({ q: v || null })}
          placeholder="Rule, trace ID or text"
          ariaLabel="Filter events"
        />
        <FilterSpacer />
        <LabeledSwitch label="Hide allowed" checked={s.hide} onCheckedChange={(v) => setFilter({ hide: v || null })} />
      </FilterRow>
      <ListWithSidebar
        open={!!s.sel}
        onClose={close}
        sidebarLabel="Trace"
        list={
          <>
            <DataTable
              ariaLabel="Events"
              data={rows}
              columns={cols}
              getRowId={(e) => e.event_id}
              selectedId={selected?.event_id ?? null}
              onRowClick={selectRow}
              keyboardNav
              loading={list.isPending}
              error={list.error}
              onRetry={() => void list.refetch()}
              emptyTitle="No requests match these filters"
              emptyMessage={`Nothing in the ${RANGE_LABEL[s.range].toLowerCase()}. Try a longer time range or fewer filters.`}
            />
            <Pagination
              page={page}
              hasNext={!!data?.hasNext}
              onPageChange={(p) => void setS({ page: p === 1 ? null : p, sel: null })}
              pageSize={size}
              pageSizes={PAGE_SIZES}
              onPageSizeChange={(n) => void setS({ size: n === 25 ? null : n, page: null, sel: null })}
            />
          </>
        }
        sidebar={s.sel && <TraceSidebar key={s.sel} id={s.sel} row={selected} nameOf={people.nameOf} />}
      />
    </>
  );
}
