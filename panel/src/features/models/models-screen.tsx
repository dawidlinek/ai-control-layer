"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable, ErrorState, ListWithSidebar, LoadingRows, PageHeader, PathIcon, ICON_PATHS, Truncate, useSelectedId } from "@/components/rogatka";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ModelInfo } from "@/lib/api/types";
import { useArtifacts } from "@/features/threats/api";
import { useConnectors, useModels } from "./api";
import { ConnectorCards, KillSwitchMessage, type KillSwitchNotice } from "./connectors";
import { dataClassesText, fileCheck, isGuardModel, isModelOff, roleText, usageText } from "./details";
import { GuardModels } from "./guard-models";
import { ModelSidebar } from "./model-sidebar";

type Row = ModelInfo & { off: boolean };

const columns: ColumnDef<Row>[] = [
  {
    id: "model",
    header: "Model",
    meta: { className: "max-w-[260px]" },
    cell: ({ row: { original: m } }) => (
      <div className={cn("flex min-w-0 flex-col", m.off && "opacity-55")}>
        <Truncate className="font-mono text-[12.5px]">{m.id}</Truncate>
        <Truncate className="text-[11.5px] text-muted">
          {roleText(m)}
          {m.off && " · off"}
        </Truncate>
      </div>
    ),
  },
  {
    id: "tier",
    header: "Runs on",
    meta: { className: "w-[80px]" },
    cell: ({ row: { original: m } }) => (
      <span
        className={cn(
          "rounded-[4px] border px-1.5 font-mono text-[11px]",
          m.tier === "cloud" ? "border-accent-line text-accent" : "border-border text-muted",
        )}
      >
        {m.tier}
      </span>
    ),
  },
  {
    id: "data",
    header: "Data it may get",
    cell: ({ row: { original: m } }) => <span className="text-muted">{dataClassesText(m.data_classes)}</span>,
  },
  {
    id: "requests",
    header: "Requests",
    meta: { className: "text-right font-mono", headerClassName: "text-right" },
    cell: ({ row: { original: m } }) => formatNumber(m.requests_day),
  },
  {
    id: "usage",
    header: "Usage today",
    meta: { className: "text-right font-mono whitespace-nowrap", headerClassName: "text-right" },
    cell: ({ row: { original: m } }) => usageText(m),
  },
  {
    id: "file",
    header: "File check",
    cell: ({ row: { original: m } }) => {
      const f = fileCheck(m);
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-[12px]",
            f.ok === true ? "text-dec-allow" : f.ok === false ? "text-dec-block" : "text-muted",
          )}
        >
          <PathIcon path={f.ok === true ? ICON_PATHS.check : f.ok === false ? ICON_PATHS.error : "M5 12h14"} size={12} strokeWidth={2.4} />
          {f.label}
        </span>
      );
    },
  },
  {
    id: "go",
    header: () => <span className="sr-only">Open</span>,
    meta: { className: "w-[14px] text-muted" },
    cell: () => <span aria-hidden>›</span>,
  },
];

export function ModelsScreen() {
  const connectors = useConnectors();
  const models = useModels();
  const artifacts = useArtifacts();
  const [sel, setSel] = useSelectedId();
  const [notice, setNotice] = React.useState<KillSwitchNotice | null>(null);

  const all = models.data ?? [];
  const conns = connectors.data ?? [];
  const rows: Row[] = all.filter((m) => !isGuardModel(m)).map((m) => ({ ...m, off: isModelOff(m, conns) }));
  const selected = rows.find((m) => m.id === sel);
  // Keep the page message in sync with the live connector state (e.g. after a refetch).
  const live = notice ? (conns.find((c) => c.id === notice.connector.id) ?? notice.connector) : null;

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Models & connectors" />
      {notice && live && <KillSwitchMessage notice={{ ...notice, connector: { ...notice.connector, kill_switch: live.kill_switch } }} />}
      {connectors.isPending ? (
        <LoadingRows rows={2} />
      ) : connectors.isError ? (
        <ErrorState title="Could not load connectors" error={connectors.error} onRetry={() => void connectors.refetch()} />
      ) : (
        <ConnectorCards connectors={conns} models={all} onResult={setNotice} />
      )}
      <ListWithSidebar
        open={!!selected}
        onClose={() => void setSel(null)}
        sidebarLabel="Model"
        list={
          <>
            <DataTable
              ariaLabel="Models"
              data={rows}
              columns={columns}
              getRowId={(m) => m.id}
              selectedId={sel}
              onRowClick={(m) => void setSel(m.id)}
              keyboardNav
              minWidth={700}
              loading={models.isPending}
              error={models.error}
              onRetry={() => void models.refetch()}
              emptyTitle="No models in the policy"
            />
            {models.isSuccess && <GuardModels models={all} />}
          </>
        }
        sidebar={selected && <ModelSidebar key={selected.id} model={selected} off={selected.off} artifacts={artifacts.data} />}
      />
    </div>
  );
}
