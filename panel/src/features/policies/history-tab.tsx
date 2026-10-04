"use client";

import * as React from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  DataTable,
  FactsGrid,
  ListWithSidebar,
  LoadingRows,
  ErrorState,
  PlainSentence,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  Truncate,
  useSelectedId,
  linkClass,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Label, Textarea } from "@/components/ui/input";
import { RequireRole } from "@/lib/auth/user-context";
import type { PolicyVersion } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { usePolicyStatus, usePolicyVersion, usePolicyVersions, useRollbackPolicy } from "./api";
import { authorOf, errorMessage, labelOf, nextVersionLabel, parseDiff, versionLabel, whenOf } from "./helpers";

const SOURCE_CLASS: Record<PolicyVersion["source"], string> = {
  file: "border-border-strong text-text",
  panel: "border-border text-muted",
  rollback: "border-border text-muted",
  startup: "border-border text-muted",
};

export function SourceChip({ source }: { source: PolicyVersion["source"] }) {
  return <span className={cn("inline-block rounded-[4px] border px-1.5 font-mono text-[11px]", SOURCE_CLASS[source])}>{source}</span>;
}

const SOURCE_TEXT: Record<PolicyVersion["source"], string> = {
  file: "edited on disk",
  panel: "published from the panel",
  rollback: "rollback from the panel",
  startup: "loaded at startup",
};

/** One plain sentence about a version (template). */
function changeSentence(v: PolicyVersion): string {
  const what = v.message.trim() || `${v.files_changed.join(", ") || "The policy"} changed`;
  const files = v.files_changed.length ? ` (${v.files_changed.join(", ")})` : "";
  switch (v.source) {
    case "file":
      return `${what}. Edited on disk${files}; Rogatka checked the file and loaded it.`;
    case "panel":
      return `${what}. Published from the panel by ${authorOf(v)}${files}.`;
    case "rollback":
      return `${what}. ${authorOf(v)} rolled the policy back from the panel${v.reason ? ` because ${v.reason}` : ""}; the history was not rewritten.`;
    default:
      return `${what}.`;
  }
}

function Diff({ diff }: { diff: string }) {
  const files = parseDiff(diff);
  if (files.length === 0) return <p className="m-0 text-[13px] text-muted">No changes to show.</p>;
  return (
    <div className="flex flex-col gap-2">
      {files.map((f) => (
        <div key={f.name} className="overflow-hidden rounded-[6px] border border-border font-mono text-[12px] leading-[1.6]">
          <div className="border-b border-border bg-raised px-2.5 py-1 font-sans text-[12px] text-muted">{f.name}</div>
          <div className="overflow-x-auto" role="list" aria-label={`Changes in ${f.name}`}>
            {f.lines.map((l, i) => (
              <div
                key={i}
                role="listitem"
                data-kind={l.kind}
                className={cn("grid grid-cols-[16px_minmax(0,1fr)] px-2.5", l.kind === "hunk" && "text-muted")}
                style={l.kind === "add" || l.kind === "del" ? { background: `color-mix(in srgb, var(${l.kind === "add" ? "--dec-allow" : "--dec-block"}) 12%, transparent)` } : undefined}
              >
                <span aria-hidden className={l.kind === "add" ? "text-dec-allow" : l.kind === "del" ? "text-dec-block" : undefined}>
                  {l.kind === "add" ? "+" : l.kind === "del" ? "−" : ""}
                </span>
                <span className="sr-only">{l.kind === "add" ? "added: " : l.kind === "del" ? "removed: " : ""}</span>
                <span className="whitespace-pre-wrap">{l.kind === "hunk" ? l.text : l.text || " "}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

const reasonSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(1, "Write why you are rolling back.")
    .min(3, "Use at least 3 characters.")
    .max(500, "Keep the reason under 500 characters."),
});

function RollbackDialog({
  version,
  next,
  open,
  onOpenChange,
  onDone,
}: {
  version: PolicyVersion;
  next: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDone: (label: string) => void;
}) {
  const rollback = useRollbackPolicy();
  const versions = usePolicyVersions();
  const form = useForm<{ reason: string }>({ resolver: zodResolver(reasonSchema), defaultValues: { reason: "" } });
  const label = labelOf(version);
  const submit = form.handleSubmit(({ reason }) =>
    rollback.mutate({ id: version.id, reason }, {
      onSuccess: (s) => {
        onDone(versionLabel(s.version, versions.data));
        form.reset();
        onOpenChange(false);
      },
    }),
  );
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) rollback.reset();
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogTitle className="m-0 text-[15px] font-semibold">Roll back to {label}?</DialogTitle>
        <DialogDescription className="m-0 text-[13px] text-muted">
          This creates a new version{next ? ` (${next})` : ""} with the same files as {label}. Every new request uses it at once. Nothing in the
          history is rewritten.
        </DialogDescription>
        <form onSubmit={submit} className="flex flex-col gap-2" noValidate>
          <Label htmlFor="rollback-reason">Reason (required)</Label>
          <Textarea id="rollback-reason" placeholder="Why roll back?" {...form.register("reason")} />
          {form.formState.errors.reason && (
            <span role="alert" className="text-[12px] text-dec-block">
              {form.formState.errors.reason.message}
            </span>
          )}
          {rollback.isError && (
            <StatusBox variant="error" title="Could not roll back">
              {errorMessage(rollback.error)}
            </StatusBox>
          )}
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="danger" disabled={rollback.isPending}>
              {rollback.isPending ? "Rolling back…" : `Roll back to ${label}`}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function VersionSidebar({ version, live, next }: { version: PolicyVersion; live: boolean; next: string | null }) {
  const detail = usePolicyVersion(version.id);
  const [dialog, setDialog] = React.useState(false);
  const [done, setDone] = React.useState<string | null>(null);
  const label = labelOf(version);
  return (
    <>
      <SidebarHeader
        label="Version"
        title={
          <>
            <span className="font-semibold">{label}</span>
            <span className="ml-2 font-sans text-[13px] text-muted">
              {whenOf(version)} · {authorOf(version)}
            </span>
          </>
        }
      />
      <SidebarBlock>
        <PlainSentence>{changeSentence(version)}</PlainSentence>
        <FactsGrid
          facts={[
            { label: "Source", value: <SourceChip source={version.source} /> },
            { label: "Who", value: authorOf(version), mono: true },
            { label: "When", value: whenOf(version), mono: true },
            { label: "Files", value: version.files_changed.join(", ") || "—", mono: true },
            { label: "How", value: SOURCE_TEXT[version.source] },
            ...(version.reason ? [{ label: "Reason", value: version.reason }] : []),
            { label: "Status", value: live ? "live now" : "not live" },
          ]}
        />
      </SidebarBlock>
      <SidebarSection title="What changed">
        {detail.isPending ? (
          <LoadingRows rows={3} />
        ) : detail.isError ? (
          <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
        ) : version.source === "startup" && !detail.data.diff ? (
          <p className="m-0 text-[13px] text-muted">The first version: every file as it was when the gateway started.</p>
        ) : (
          <Diff diff={detail.data.diff} />
        )}
      </SidebarSection>
      {done && (
        <div className="px-3.5 pt-3">
          <StatusBox variant="success" title={`${done} is live`}>
            Rolled back to {label} · saved as policy {done}. New requests use it now.
          </StatusBox>
        </div>
      )}
      <SidebarActions className="items-center">
        {live ? (
          <span className="text-[13px] text-muted">This is the live version.</span>
        ) : (
          <RequireRole
            min="admin"
            fallback={
              <Button disabled title="Only admins can roll back the policy">
                Roll back to this version…
              </Button>
            }
          >
            <Button onClick={() => setDialog(true)}>Roll back to this version…</Button>
            <RollbackDialog version={version} next={next} open={dialog} onOpenChange={setDialog} onDone={setDone} />
          </RequireRole>
        )}
        <Link href={`/traffic?q=${encodeURIComponent(version.version)}`} className={cn(linkClass, "text-[13px]")}>
          First requests on {label} →
        </Link>
      </SidebarActions>
    </>
  );
}

export function HistoryTab() {
  const versions = usePolicyVersions();
  const status = usePolicyStatus();
  const [sel, setSel] = useSelectedId();
  const rows = versions.data ?? [];
  const selected = rows.find((v) => String(v.id) === sel);
  const liveVersion = status.data?.version;
  const next = nextVersionLabel(versions.data);

  const columns = React.useMemo<ColumnDef<PolicyVersion>[]>(
    () => [
      {
        id: "version",
        header: "Version",
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <b className="font-mono font-semibold">{labelOf(row.original)}</b>
            {row.original.version === liveVersion && <span className="text-[11px] text-dec-allow">live</span>}
          </span>
        ),
        meta: { className: "w-[90px]" },
      },
      {
        id: "when",
        header: "When · who",
        cell: ({ row }) => (
          <span className="flex flex-col whitespace-nowrap">
            <span>{whenOf(row.original)}</span>
            <span className="text-[12px] text-muted">{authorOf(row.original)}</span>
          </span>
        ),
        meta: { className: "w-[150px]" },
      },
      { id: "source", header: "Source", cell: ({ row }) => <SourceChip source={row.original.source} />, meta: { className: "w-[90px]" } },
      {
        id: "change",
        header: "Change",
        cell: ({ row: { original: v } }) => (
          <Truncate>{v.reason ? `Rolled back: ${v.reason}` : v.message || v.files_changed.join(", ")}</Truncate>
        ),
        meta: { className: "max-w-[420px]" },
      },
      { id: "go", header: "", cell: () => <span aria-hidden className="text-muted">›</span>, meta: { className: "w-[14px]" } },
    ],
    [liveVersion],
  );

  return (
    <ListWithSidebar
      open={!!selected}
      onClose={() => void setSel(null)}
      sidebarLabel="Version"
      list={
        <DataTable
          ariaLabel="Versions"
          data={rows}
          columns={columns}
          getRowId={(v) => String(v.id)}
          selectedId={sel}
          onRowClick={(v) => void setSel(String(v.id))}
          keyboardNav
          minWidth={600}
          loading={versions.isPending}
          error={versions.error}
          onRetry={() => void versions.refetch()}
          emptyTitle="No versions yet"
        />
      }
      sidebar={selected && <VersionSidebar key={selected.id} version={selected} live={selected.version === liveVersion} next={next} />}
    />
  );
}
