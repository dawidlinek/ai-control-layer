"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable, DecisionBadge, ListWithSidebar, RuleChip, Truncate } from "@/components/rogatka";
import { useRuleHits } from "./api";
import { hitsText, ModeLabel, RuleSidebar } from "./rule-sidebar";
import type { PolicyRule } from "./rules";
import { usePolicyRules } from "./use-rules";

export function RulesTab({
  ruleId,
  onSelectRule,
  query,
  onOpenYaml,
}: {
  ruleId: string | null;
  onSelectRule: (id: string | null) => void;
  query: string;
  onOpenYaml: (rule: PolicyRule) => void;
}) {
  const { rules, controls, isPending, error, refetch } = usePolicyRules();
  const hits = useRuleHits();

  const q = query.trim().toLowerCase();
  const rows = React.useMemo(
    () => (rules ?? []).filter((r) => !q || [r.id, r.what, r.typeLabel, r.type, r.action].some((s) => s.toLowerCase().includes(q))),
    [rules, q],
  );
  const selected = rows.find((r) => r.id === ruleId);

  const columns = React.useMemo<ColumnDef<PolicyRule>[]>(
    () => [
      {
        id: "rule",
        header: "Rule",
        cell: ({ row }) => <RuleChip ruleId={row.original.id} locked={row.original.locked} href={false} />,
        meta: { className: "w-[150px] whitespace-nowrap" },
      },
      {
        id: "what",
        header: "What it does",
        cell: ({ row }) => <Truncate>{row.original.what}</Truncate>,
        meta: { className: "max-w-[360px]" },
      },
      {
        id: "action",
        header: "Action",
        cell: ({ row }) => <DecisionBadge decision={row.original.action} />,
        meta: { className: "w-[150px]" },
      },
      { id: "mode", header: "Mode", cell: ({ row }) => <ModeLabel mode={row.original.mode} />, meta: { className: "w-[80px]" } },
      {
        id: "hits",
        header: "Hits 24 h",
        cell: ({ row }) => hitsText(hits.data, row.original.id),
        meta: { className: "w-[80px] text-right font-mono", headerClassName: "text-right" },
      },
      { id: "go", header: "", cell: () => <span aria-hidden className="text-muted">›</span>, meta: { className: "w-[14px]" } },
    ],
    [hits.data],
  );

  return (
    <ListWithSidebar
      open={!!selected}
      onClose={() => onSelectRule(null)}
      sidebarLabel="Rule"
      list={
        <DataTable
          ariaLabel="Rules"
          data={rows}
          columns={columns}
          getRowId={(r) => r.id}
          selectedId={ruleId}
          onRowClick={(r) => onSelectRule(r.id)}
          keyboardNav
          minWidth={680}
          loading={isPending}
          error={error}
          onRetry={refetch}
          emptyTitle={q ? "No rules match" : "No rules"}
          emptyMessage={q ? "Try a rule ID or a topic such as “injection”." : undefined}
        />
      }
      sidebar={selected && <RuleSidebar rule={selected} hits={hits.data} controlsFile={controls.data} onOpenYaml={() => onOpenYaml(selected)} />}
    />
  );
}
