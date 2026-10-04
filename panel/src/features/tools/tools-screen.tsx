"use client";

import * as React from "react";
import { parseAsArrayOf, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import type { ColumnDef } from "@tanstack/react-table";
import {
  DataTable,
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  ListWithSidebar,
  PageHeader,
  SegmentedTabs,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { formatNumber } from "@/lib/format";
import { useEvents24h } from "@/features/threats/api";
import { useMcpServers, useMcpTools } from "./api";
import { BUILTINS, toRow, type ToolRow } from "./catalogue";
import { RuleText, StatusChip } from "./status-chip";
import { ToolSidebar } from "./tool-sidebar";

const TABS = ["all", "quarantined", "approval"] as const;
type Tab = (typeof TABS)[number];

const TAB_TEST: Record<Tab, (r: ToolRow) => boolean> = {
  all: () => true,
  quarantined: (r) => r.status === "quarantined",
  approval: (r) => r.rule === "needs approval",
};

type Row = ToolRow & { calls: number | undefined };

const columns: ColumnDef<Row>[] = [
  {
    id: "tool",
    header: "Tool",
    meta: { className: "max-w-[260px]" },
    cell: ({ row: { original: r } }) => (
      <div className="flex min-w-0 flex-col">
        <Truncate className="font-mono text-[12.5px]">{r.id}</Truncate>
        <Truncate className="text-[11.5px] text-muted">{r.serverLabel}</Truncate>
      </div>
    ),
  },
  { id: "status", header: "Status", meta: { className: "w-[120px]" }, cell: ({ row: { original: r } }) => <StatusChip status={r.status} /> },
  { id: "rule", header: "Rule", meta: { className: "w-[130px]" }, cell: ({ row: { original: r } }) => <RuleText rule={r.rule} /> },
  {
    id: "who",
    header: "Who can use it",
    meta: { className: "max-w-[220px] text-muted" },
    cell: ({ row: { original: r } }) => <Truncate>{r.who.length ? r.who.join(", ") : r.status === "denied" ? "nobody" : "—"}</Truncate>,
  },
  {
    id: "calls",
    header: "Calls 24 h",
    meta: { className: "w-[80px] text-right font-mono", headerClassName: "text-right" },
    cell: ({ row: { original: r } }) => (r.calls === undefined ? "—" : formatNumber(r.calls)),
  },
  {
    id: "go",
    header: () => <span className="sr-only">Open</span>,
    meta: { className: "w-[14px] text-muted" },
    cell: () => <span aria-hidden>›</span>,
  },
];

export function ToolsScreen() {
  const tools = useMcpTools();
  const servers = useMcpServers();
  const events = useEvents24h();
  const [sel, setSel] = useSelectedId();
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("all"));
  const [serverFilter, setServerFilter] = useQueryState("server", parseAsArrayOf(parseAsString).withDefault([]));
  const [whoFilter, setWhoFilter] = useQueryState("who", parseAsArrayOf(parseAsString).withDefault([]));

  const all: Row[] = React.useMemo(() => {
    const rows = [...(tools.data ?? []).map((t) => toRow(t, servers.data ?? [])), ...BUILTINS];
    const counts = new Map<string, number>();
    for (const e of events.data ?? []) if (e.tool) counts.set(e.tool, (counts.get(e.tool) ?? 0) + 1);
    return rows.map((r) => ({
      ...r,
      calls: events.data ? r.eventNames.reduce((s, n) => s + (counts.get(n) ?? 0), 0) : undefined,
    }));
  }, [tools.data, servers.data, events.data]);

  const filtered = all
    .filter((r) => (serverFilter.length ? serverFilter.includes(r.server) : true))
    .filter((r) => (whoFilter.length ? r.who.some((w) => whoFilter.includes(w)) : true));
  const rows = filtered.filter(TAB_TEST[tab]);
  const selected = rows.find((r) => r.id === sel);

  const serverOptions = Array.from(new Set(all.map((r) => r.server))).map((s) => ({ value: s, label: s }));
  const whoOptions = Array.from(new Set(all.flatMap((r) => r.who)))
    .sort()
    .map((w) => ({ value: w, label: w }));

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Tools & MCP" />
      <FilterRow>
        <SegmentedTabs
          ariaLabel="Status"
          value={tab}
          onChange={(v) => void setTab(v === "all" ? null : v)}
          tabs={[
            { value: "all", label: "All", count: filtered.length },
            { value: "quarantined", label: "Quarantined", count: filtered.filter(TAB_TEST.quarantined).length },
            { value: "approval", label: "Need approval", count: filtered.filter(TAB_TEST.approval).length },
          ]}
        />
        <FilterMenuButton label="Server" options={serverOptions} selected={serverFilter} onChange={(v) => void setServerFilter(v.length ? v : null)} />
        <FilterMenuButton label="Who can use it" options={whoOptions} selected={whoFilter} onChange={(v) => void setWhoFilter(v.length ? v : null)} />
        <FilterSpacer />
        <Button disabled title="Not available in the admin API yet: MCP servers are added in tools.yaml">
          + Add MCP server
        </Button>
      </FilterRow>
      <ListWithSidebar
        open={!!selected}
        onClose={() => void setSel(null)}
        sidebarLabel="Tool"
        list={
          <DataTable
            ariaLabel="Tools"
            data={rows}
            columns={columns}
            getRowId={(r) => r.id}
            selectedId={sel}
            onRowClick={(r) => void setSel(r.id)}
            keyboardNav
            minWidth={680}
            loading={tools.isPending}
            error={tools.error}
            onRetry={() => void tools.refetch()}
            emptyTitle={tab === "quarantined" ? "Nothing is quarantined" : "No tools match these filters"}
          />
        }
        sidebar={selected && <ToolSidebar key={selected.id} row={selected} calls={selected.calls} />}
      />
    </div>
  );
}
