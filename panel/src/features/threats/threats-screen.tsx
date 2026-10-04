"use client";

import { debounce, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import type { ColumnDef } from "@tanstack/react-table";
import {
  DataTable,
  DecisionBadge,
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  ListWithSidebar,
  PageHeader,
  SearchInput,
  SegmentedTabs,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { RequireRole, useHasRole } from "@/lib/auth/user-context";
import { formatNumber } from "@/lib/format";
import type { ArtifactScanResult, FeedSignature, FeedTarget } from "@/lib/api/types";
import { AddRuleForm } from "./add-rule";
import { useArtifacts, useSignatures } from "./api";
import { fileResult, findingLabel } from "./artifact-copy";
import { FeedBar } from "./feed-bar";
import { LOOKS_AT, looksAt } from "./signatures";
import { FileSidebar, ResultLabel, SignatureSidebar } from "./sidebars";

const TABS = ["signatures", "files"] as const;

const TARGETS = Object.keys(LOOKS_AT) as FeedTarget[];

const sigColumns: ColumnDef<FeedSignature>[] = [
  { id: "id", header: "Rule", meta: { className: "w-[130px] font-mono text-[12px] whitespace-nowrap" }, cell: ({ row }) => row.original.id },
  {
    id: "what",
    header: "What it catches",
    meta: { className: "max-w-[320px]" },
    cell: ({ row: { original: s } }) => (
      <div className="flex min-w-0 flex-col">
        <Truncate>{s.title}</Truncate>
        <Truncate className="text-[12px] text-muted">{s.source || (s.origin === "policy" ? "offline baseline" : "")}</Truncate>
      </div>
    ),
  },
  { id: "looks", header: "Looks at", meta: { className: "w-[130px] text-muted" }, cell: ({ row }) => looksAt(row.original.target) },
  { id: "action", header: "Action", meta: { className: "w-[110px]" }, cell: ({ row }) => <DecisionBadge decision={row.original.action} /> },
  {
    id: "hits",
    header: "Hits 24 h",
    meta: { className: "w-[72px] text-right font-mono", headerClassName: "text-right" },
    cell: ({ row: { original: s } }) => (s.hits_24h === null ? "—" : formatNumber(s.hits_24h)),
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
  const [target, setTarget] = useQueryState("target", parseAsStringLiteral(TARGETS));
  const [q, setQ] = useQueryState("q", parseAsString.withDefault("").withOptions({ limitUrlUpdates: debounce(300) }));
  const [sel, setSel] = useSelectedId();
  const isAdmin = useHasRole("admin");
  const signatures = useSignatures({ target: target ?? undefined, q });
  const artifacts = useArtifacts();

  const sigs = signatures.data ?? [];
  const files = artifacts.data ?? [];
  const adding = tab === "signatures" && sel === "new" && isAdmin;
  const selectedSig = tab === "signatures" && !adding ? sigs.find((s) => s.id === sel) : undefined;
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
            { value: "signatures", label: "Signatures", count: signatures.total },
            { value: "files", label: "Model files", count: artifacts.data ? files.length : undefined },
          ]}
        />
        {tab === "signatures" && (
          <>
            <FilterMenuButton
              label="Looks at"
              multiple={false}
              options={TARGETS.map((t) => ({ value: t, label: LOOKS_AT[t] }))}
              selected={target ? [target] : []}
              onChange={(v) => void setTarget((v[0] as FeedTarget | undefined) ?? null)}
            />
            <SearchInput value={q} onChange={(v) => void setQ(v || null)} placeholder="Search rules" ariaLabel="Search signatures" />
          </>
        )}
        <FilterSpacer />
        {tab === "signatures" && (
          <RequireRole
            min="admin"
            fallback={
              <Button variant="primary" size="lg" disabled title="Only admins can add rules">
                + Add rule
              </Button>
            }
          >
            <Button variant="primary" size="lg" onClick={() => void setSel("new")}>
              + Add rule
            </Button>
          </RequireRole>
        )}
      </FilterRow>
      {tab === "signatures" ? (
        <ListWithSidebar
          open={!!selectedSig || adding}
          onClose={() => void setSel(null)}
          sidebarLabel={adding ? "New rule" : "Signature"}
          list={
            <>
              <DataTable
                ariaLabel="Signatures"
                data={sigs}
                columns={sigColumns}
                getRowId={(s) => s.id}
                selectedId={sel}
                onRowClick={(s) => void setSel(s.id)}
                keyboardNav
                minWidth={660}
                loading={signatures.isPending}
                error={signatures.error}
                onRetry={() => void signatures.refetch()}
                emptyTitle={q || target ? "No signature matches" : "No signatures in the active bundle"}
                emptyMessage={q || target ? "Try another search or clear the filter." : undefined}
              />
              {signatures.total !== undefined && signatures.total > sigs.length && (
                <p className="m-0 text-[12px] text-muted">
                  Showing {formatNumber(sigs.length)} of {formatNumber(signatures.total)} signatures. Narrow the search to see the rest.
                </p>
              )}
            </>
          }
          sidebar={adding ? <AddRuleForm /> : selectedSig && <SignatureSidebar key={selectedSig.id} sig={selectedSig} />}
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
