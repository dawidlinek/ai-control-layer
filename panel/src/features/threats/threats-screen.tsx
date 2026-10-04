"use client";

import * as React from "react";
import { parseAsStringLiteral, useQueryState } from "nuqs";
import type { ColumnDef } from "@tanstack/react-table";
import {
  DataTable,
  DecisionBadge,
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
import type { ArtifactScanResult, EventSummary } from "@/lib/api/types";
import { useArtifacts, useEvents24h, useFeedStatus } from "./api";
import { fileResult, findingLabel } from "./artifact-copy";
import { FeedBar } from "./feed-bar";
import { SIGNATURES, type Signature } from "./signatures";
import { FileSidebar, ResultLabel, SignatureSidebar } from "./sidebars";

const TABS = ["signatures", "files"] as const;

type SigRow = Signature & { hits: number | undefined };

const ADD_RULE_GAP =
  "Not available in the admin API yet: add the rule on the feed server, then use Sync now. The panel cannot list or publish signatures.";

const sigColumns: ColumnDef<SigRow>[] = [
  { id: "id", header: "Rule", meta: { className: "w-[130px] font-mono text-[12px] whitespace-nowrap" }, cell: ({ row }) => row.original.id },
  {
    id: "what",
    header: "What it catches",
    meta: { className: "max-w-[320px]" },
    cell: ({ row: { original: s } }) => (
      <div className="flex min-w-0 flex-col">
        <Truncate>{s.what}</Truncate>
        <Truncate className="text-[12px] text-muted">{s.source}</Truncate>
      </div>
    ),
  },
  { id: "looks", header: "Looks at", meta: { className: "w-[130px] text-muted" }, cell: ({ row }) => row.original.looksAt },
  { id: "action", header: "Action", meta: { className: "w-[110px]" }, cell: ({ row }) => <DecisionBadge decision={row.original.action} /> },
  {
    id: "hits",
    header: "Hits 24 h",
    meta: { className: "w-[72px] text-right font-mono", headerClassName: "text-right" },
    cell: ({ row: { original: s } }) => (s.hits === undefined ? "—" : formatNumber(s.hits)),
  },
  { id: "go", header: () => <span className="sr-only">Open</span>, meta: { className: "w-[14px] text-muted" }, cell: () => <span aria-hidden>›</span> },
];

const fileColumns: ColumnDef<ArtifactScanResult>[] = [
  {
    id: "file",
    header: "File",
    meta: { className: "max-w-[280px]" },
    cell: ({ row }) => <Truncate className="font-mono text-[12px]">{row.original.filename}</Truncate>,
  },
  { id: "format", header: "Format", meta: { className: "w-[100px] text-muted" }, cell: ({ row }) => row.original.format_detected },
  { id: "result", header: "Result", meta: { className: "w-[110px]" }, cell: ({ row }) => <ResultLabel result={fileResult(row.original)} /> },
  {
    id: "finding",
    header: "Finding",
    meta: { className: "max-w-[260px] text-muted" },
    cell: ({ row }) => <Truncate>{findingLabel(row.original)}</Truncate>,
  },
  { id: "go", header: () => <span className="sr-only">Open</span>, meta: { className: "w-[14px] text-muted" }, cell: () => <span aria-hidden>›</span> },
];

export function ThreatsScreen() {
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("signatures"));
  const [sel, setSel] = useSelectedId();
  const feed = useFeedStatus();
  const events = useEvents24h();
  const artifacts = useArtifacts();

  const hitsByRule = React.useMemo(() => {
    if (!events.data) return undefined;
    const m = new Map<string, EventSummary[]>();
    for (const e of events.data) for (const r of e.rule_ids) m.set(r, [...(m.get(r) ?? []), e]);
    return m;
  }, [events.data]);

  const sigRows: SigRow[] = SIGNATURES.map((s) => ({ ...s, hits: hitsByRule ? (hitsByRule.get(s.id)?.length ?? 0) : undefined }));
  const files = artifacts.data ?? [];

  const selectedSig = tab === "signatures" ? sigRows.find((s) => s.id === sel) : undefined;
  const selectedFile = tab === "files" ? files.find((f) => f.id === sel) : undefined;

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Known threats" />
      <FeedBar />
      <FilterRow>
        <SegmentedTabs
          ariaLabel="View"
          value={tab}
          onChange={(v) => {
            void setSel(null);
            void setTab(v === "signatures" ? null : v);
          }}
          tabs={[
            { value: "signatures", label: "Signatures", count: sigRows.length },
            { value: "files", label: "Model files", count: artifacts.data ? files.length : undefined },
          ]}
        />
        <FilterSpacer />
        {tab === "signatures" && (
          <Button variant="primary" size="lg" disabled title={ADD_RULE_GAP}>
            + Add rule
          </Button>
        )}
      </FilterRow>
      {tab === "signatures" ? (
        <ListWithSidebar
          open={!!selectedSig}
          onClose={() => void setSel(null)}
          sidebarLabel="Signature"
          list={
            <>
              <DataTable
                ariaLabel="Signatures"
                data={sigRows}
                columns={sigColumns}
                getRowId={(s) => s.id}
                selectedId={sel}
                onRowClick={(s) => void setSel(s.id)}
                keyboardNav
                minWidth={660}
              />
              <p className="m-0 text-[12px] text-muted">
                Headline rules of the seed bundle
                {feed.data ? ` (the active bundle has ${formatNumber(feed.data.entries)} rules)` : ""}. The admin API does not list
                signatures yet.
              </p>
            </>
          }
          sidebar={selectedSig && <SignatureSidebar key={selectedSig.id} sig={selectedSig} hits={hitsByRule ? (hitsByRule.get(selectedSig.id) ?? []) : undefined} />}
        />
      ) : (
        <ListWithSidebar
          open={!!selectedFile}
          onClose={() => void setSel(null)}
          sidebarLabel="Model file"
          list={
            <DataTable
              ariaLabel="Model files"
              data={files}
              columns={fileColumns}
              getRowId={(f) => f.id}
              selectedId={sel}
              onRowClick={(f) => void setSel(f.id)}
              keyboardNav
              minWidth={620}
              loading={artifacts.isPending}
              error={artifacts.error}
              onRetry={() => void artifacts.refetch()}
              emptyTitle="No model files scanned yet"
            />
          }
          sidebar={selectedFile && <FileSidebar key={selectedFile.id} file={selectedFile} />}
        />
      )}
    </div>
  );
}
