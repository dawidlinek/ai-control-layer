"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { parseAsStringLiteral, useQueryState } from "nuqs";
import {
  DataTable,
  EmptyState,
  ErrorState,
  FactsGrid,
  FilterRow,
  ListWithSidebar,
  LoadingRows,
  PageHeader,
  PathIcon,
  ICON_PATHS,
  PlainSentence,
  PlaceholderChip,
  SegmentedTabs,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useHasRole } from "@/lib/auth/user-context";
import type { InsightCluster } from "@/lib/api/types";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useInsightClusters, usePublishSkill, type PublishInput } from "./api";
import { draftOf, fillTemplate, howOften, specialistOf, timeItTakes, type SpecialistInfo } from "./model";

const TABS = ["tasks", "skills", "specialist"] as const;
const SUBTITLE =
  "Found in masked prompts, on local models. Patterns used by fewer than 5 people are hidden. People see only their own suggestions.";
const NO_DISMISS = "Not available in the admin API yet (there is no dismiss endpoint).";
const PRESETS = ["monitor", "balanced", "strict", "paranoid"] as const;

export function InsightsScreen() {
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("tasks"));
  const clusters = useInsightClusters();
  const all = clusters.data ?? [];
  const tasks = all.filter((c) => c.status !== "dismissed");
  const skills = all.filter((c) => c.status === "published");
  const specialist = specialistOf(all);

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Automation Insights" subtitle={SUBTITLE} />
      <FilterRow>
        <SegmentedTabs
          ariaLabel="View"
          value={tab}
          onChange={(t) => void setTab(t)}
          tabs={[
            { value: "tasks", label: "Repeated tasks", count: clusters.data ? tasks.length : undefined },
            { value: "skills", label: "Skills", count: clusters.data ? skills.length : undefined },
            { value: "specialist", label: "Specialist models", count: clusters.data ? (specialist ? 1 : 0) : undefined },
          ]}
        />
      </FilterRow>
      {tab === "tasks" && <TasksTab clusters={tasks} loading={clusters.isPending} error={clusters.error} onRetry={() => void clusters.refetch()} />}
      {tab === "skills" && <SkillsTab skills={skills} loading={clusters.isPending} error={clusters.error} onRetry={() => void clusters.refetch()} />}
      {tab === "specialist" &&
        (clusters.isPending ? (
          <LoadingRows rows={3} />
        ) : clusters.error ? (
          <ErrorState error={clusters.error} onRetry={() => void clusters.refetch()} />
        ) : (
          <SpecialistTab info={specialist} />
        ))}
    </div>
  );
}

interface ListProps {
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}

/* ---------------------------------------------------------------- Repeated tasks */

function StatusPill({ status }: { status: InsightCluster["status"] }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-[10px] border px-2 py-px text-[12px]",
        status === "published" ? "border-dec-allow/45 text-dec-allow" : "border-accent-line bg-accent-soft text-text",
      )}
    >
      {status === "published" && <PathIcon path={ICON_PATHS.check} size={11} strokeWidth={2.4} />}
      {status}
    </span>
  );
}

function TasksTab({ clusters, ...state }: ListProps & { clusters: InsightCluster[] }) {
  const [sel, setSel] = useSelectedId();
  const selected = clusters.find((c) => c.id === sel);
  const columns = React.useMemo<ColumnDef<InsightCluster>[]>(
    () => [
      {
        id: "task",
        header: "Repeated task",
        meta: { className: "max-w-[320px] font-medium" },
        cell: ({ row }) => <Truncate>{row.original.label}</Truncate>,
      },
      { id: "group", header: "Group", meta: { className: "text-muted" }, cell: ({ row }) => row.original.group },
      {
        id: "people",
        header: () => <span className="block text-right">People</span>,
        meta: { className: "text-right font-mono" },
        cell: ({ row }) => row.original.distinct_users,
      },
      { id: "often", header: "How often", meta: { className: "text-muted" }, cell: ({ row }) => howOften(row.original) },
      { id: "time", header: "Time it takes", cell: ({ row }) => timeItTakes(row.original) },
      { id: "status", header: "Status", cell: ({ row }) => <StatusPill status={row.original.status} /> },
      {
        id: "go",
        header: () => <span className="sr-only">Open</span>,
        meta: { className: "w-[14px] text-muted" },
        cell: () => <span aria-hidden>›</span>,
      },
    ],
    [],
  );
  return (
    <ListWithSidebar
      open={!!selected}
      onClose={() => void setSel(null)}
      sidebarLabel="Repeated task"
      list={
        <DataTable
          ariaLabel="Repeated tasks"
          data={clusters}
          columns={columns}
          getRowId={(c) => c.id}
          selectedId={sel}
          onRowClick={(c) => void setSel(c.id)}
          keyboardNav
          minWidth={660}
          loading={state.loading}
          error={state.error}
          onRetry={state.onRetry}
          emptyTitle="No repeated tasks yet"
          emptyMessage="Patterns show up once at least 5 people in a group ask for the same kind of thing."
        />
      }
      sidebar={selected && <TaskSidebar key={selected.id} cluster={selected} />}
    />
  );
}

function TemplateView({ template, values }: { template: string; values?: Record<string, string> }) {
  return (
    <>
      {fillTemplate(template, values).map((p, i) =>
        "text" in p ? (
          <React.Fragment key={i}>{p.text}</React.Fragment>
        ) : p.value !== null ? (
          <mark key={i} data-filled={p.name} className="rounded-[3px] bg-accent-soft px-0.5 text-text">
            {p.value}
          </mark>
        ) : (
          <span key={i} data-placeholder={p.name} className="text-accent">
            {`{${p.name}}`}
          </span>
        ),
      )}
    </>
  );
}

/** Render example text with `<PERSON_1>`-style placeholders as placeholder chips. */
function WithPlaceholders({ text }: { text: string }) {
  const parts = text.split(/(<[A-Z][A-Z_]*_\d+>)/g);
  return (
    <>
      {parts.map((p, i) => (/^<[A-Z][A-Z_]*_\d+>$/.test(p) ? <PlaceholderChip key={i}>{p}</PlaceholderChip> : <React.Fragment key={i}>{p}</React.Fragment>))}
    </>
  );
}

function TaskSidebar({ cluster }: { cluster: InsightCluster }) {
  const isAdmin = useHasRole("admin");
  const publish = usePublishSkill();
  const [trying, setTrying] = React.useState(false);
  const draft = draftOf(cluster);
  const published = cluster.status === "published";
  const justPublished = publish.isSuccess;
  const preset = (PRESETS as readonly string[]).includes(draft.preset ?? "") ? (draft.preset as PublishInput["preset"]) : "strict";
  const canPublish = !published && !!draft.model;

  const facts = [
    { label: "Group", value: cluster.group },
    { label: "People", value: String(cluster.distinct_users), mono: true },
    { label: "How often", value: howOften(cluster) },
    { label: "Time it takes", value: timeItTakes(cluster) },
    ...draft.facts.map(([label, value]) => ({ label, value })),
  ];

  return (
    <>
      <SidebarHeader label="Repeated task" title={cluster.id} copyText={cluster.id} />
      <SidebarBlock>
        <b className="text-[14px] font-semibold">{cluster.label}</b>
        <PlainSentence>{cluster.task_card || `${cluster.distinct_users} people in ${cluster.group} ask for this ${howOften(cluster)}.`}</PlainSentence>
        <FactsGrid facts={facts} />
      </SidebarBlock>
      <SidebarSection title={published ? "Skill" : "Draft skill"}>
        <dl className="m-0 grid grid-cols-[80px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[12.5px]">
          <dt className="text-muted">Name</dt>
          <dd className="m-0 font-mono text-[12px] [overflow-wrap:anywhere]">{draft.name}</dd>
          {draft.template && (
            <>
              <dt className="text-muted">Template</dt>
              <dd className="m-0 font-mono text-[12px] [overflow-wrap:anywhere]">
                <TemplateView template={draft.template} />
              </dd>
            </>
          )}
          {draft.inputs.length > 0 && (
            <>
              <dt className="text-muted">Inputs</dt>
              <dd className="m-0 font-mono text-[12px] [overflow-wrap:anywhere]">{draft.inputs.join(", ")}</dd>
            </>
          )}
          <dt className="text-muted">Model</dt>
          <dd className="m-0 font-mono text-[12px]">{draft.model ?? "—"}</dd>
          {draft.rules && (
            <>
              <dt className="text-muted">Rules</dt>
              <dd className="m-0 font-mono text-[12px] [overflow-wrap:anywhere]">{draft.rules}</dd>
            </>
          )}
        </dl>
        {trying && draft.template && (
          <div aria-label="Example" role="region" className="flex flex-col gap-1.5 rounded-[6px] border border-border bg-inset p-2.5">
            <span className="text-[11px] font-semibold uppercase tracking-[.08em] text-muted">With an example</span>
            <p className="m-0 font-mono text-[12px] leading-[1.55] [overflow-wrap:anywhere]">
              <TemplateView template={draft.template} values={draft.example} />
            </p>
            <span className="text-[12px] text-muted">
              {Object.keys(draft.example).length
                ? "Filled in here from a masked example; nothing is sent to a model."
                : "No example is stored for this task; placeholders stay empty."}
            </span>
          </div>
        )}
        {cluster.examples_redacted.length > 0 && (
          <details className="text-[12.5px]">
            <summary className="cursor-pointer text-muted">Masked prompts it was found in ({cluster.examples_redacted.length})</summary>
            <ul className="m-0 mt-1.5 flex list-none flex-col gap-1 p-0">
              {cluster.examples_redacted.map((e, i) => (
                <li key={i} className="rounded-[4px] bg-inset px-2 py-1 font-mono text-[12px]">
                  <WithPlaceholders text={e} />
                </li>
              ))}
            </ul>
          </details>
        )}
      </SidebarSection>
      <div className="flex flex-col gap-2.5 px-3.5 pt-3.5">
        {justPublished && (
          <StatusBox variant="success" title="Published">
            {draft.name} is live for {cluster.group}. It shows up in their clients on the next model refresh.
            {publish.data.version ? ` Saved as policy ${publish.data.version}.` : " Saved as a new policy version."}
          </StatusBox>
        )}
        {published && !justPublished && (
          <StatusBox variant="success">
            Published as {draft.name}
            {draft.runs30d !== null ? ` · used ${formatNumber(draft.runs30d)} times in 30 days` : ""}
            {draft.publishedVersion ? ` · policy ${draft.publishedVersion}` : ""}.
          </StatusBox>
        )}
        {publish.isError && (
          <StatusBox variant="error" title="Could not publish the skill">
            {publish.error.message}
          </StatusBox>
        )}
      </div>
      <SidebarActions>
        <Button onClick={() => setTrying((t) => !t)} aria-pressed={trying} disabled={!draft.template}>
          {trying ? "Hide the example" : "Try with an example"}
        </Button>
        {!published && (
          <>
            <Button
              variant="primary"
              disabled={!isAdmin || !canPublish || publish.isPending}
              title={!isAdmin ? "Only admins can publish skills" : !draft.model ? "The draft has no model yet" : undefined}
              onClick={() => publish.mutate({ cluster, skillId: draft.name, model: draft.model!, preset })}
            >
              {publish.isPending ? "Publishing…" : "Publish skill"}
            </Button>
            <Button variant="ghost" disabled title={NO_DISMISS}>
              Dismiss
            </Button>
          </>
        )}
      </SidebarActions>
      {!published && (
        <p className="m-0 px-3.5 pb-3.5 text-[12px] text-muted">
          Publishing adds the skill to the policy for {cluster.group} (a new policy version) and it appears in their clients’ model list.
        </p>
      )}
    </>
  );
}

/* ---------------------------------------------------------------- Skills */

function SkillsTab({ skills, ...state }: ListProps & { skills: InsightCluster[] }) {
  const columns = React.useMemo<ColumnDef<InsightCluster>[]>(
    () => [
      { id: "skill", header: "Skill", meta: { className: "font-mono" }, cell: ({ row }) => draftOf(row.original).name },
      { id: "to", header: "Available to", meta: { className: "text-muted" }, cell: ({ row }) => row.original.group },
      {
        id: "runs",
        header: () => <span className="block text-right">Runs 30 d</span>,
        meta: { className: "text-right font-mono" },
        cell: ({ row }) => {
          const n = draftOf(row.original).runs30d;
          return n === null ? "—" : formatNumber(n);
        },
      },
      {
        id: "cost",
        header: "Cost per run, before → now",
        meta: { className: "font-mono" },
        cell: ({ row }) => {
          const d = draftOf(row.original);
          return d.costBefore && d.costNow ? `${d.costBefore} → ${d.costNow}` : (d.costNow ?? "—");
        },
      },
    ],
    [],
  );
  return (
    <DataTable
      ariaLabel="Skills"
      data={skills}
      columns={columns}
      getRowId={(c) => c.id}
      minWidth={600}
      loading={state.loading}
      error={state.error}
      onRetry={state.onRetry}
      emptyTitle="No skills published yet"
      emptyMessage="Publish a draft skill from Repeated tasks."
    />
  );
}

/* ---------------------------------------------------------------- Specialist models */

type StepState = "done" | "not done";

function SpecialistTab({ info }: { info: SpecialistInfo | null }) {
  if (!info) {
    return (
      <div className="rounded-[8px] border border-border bg-surface">
        <EmptyState title="No specialist models">Repeated tasks run on the general models (gemini/flash, gemini/pro, local/qwen3.8-27b).</EmptyState>
      </div>
    );
  }
  const base = info.base ?? "the local Qwen";
  const steps: Array<{ label: string; state: StepState; note?: string }> = [
    { label: `${formatNumber(info.examples)} masked examples`, state: "done" },
    { label: "trained offline", state: "not done", note: "not used: no fine-tune, the prompt does the work" },
    { label: "file scanned", state: "not done", note: `no new model file; it runs on ${base}` },
    { label: `registered as ${info.id}`, state: "done" },
    { label: "evaluated", state: info.evaluation.length ? "done" : "not done" },
    { label: "used by auto", state: "done" },
  ];
  return (
    <section aria-label="Specialist models" className="flex flex-col gap-3.5 rounded-[8px] border border-border bg-surface p-4">
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="m-0 font-mono text-[14px] font-semibold">{info.id}</h2>
        <span className="text-[12.5px] text-muted">prompt-configured on {base} · not a fine-tuned model</span>
      </div>
      <p className="m-0 max-w-[720px] text-[13px] leading-[1.5]">
        {info.id} is {base} with a fixed system prompt, output format and worked examples
        {info.method ? ` (${info.method})` : ""}. No model was trained or fine-tuned for it, so there is no separate model file to scan:
        the steps a trained specialist would need are marked as not done.
      </p>
      <ol aria-label="Pipeline" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
        {steps.map((s) => (
          <li
            key={s.label}
            data-state={s.state}
            title={s.note}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-[14px] border px-2.5 py-[5px] text-[12.5px]",
              s.state === "done" ? "border-dec-allow/40 text-text" : "border-dashed border-border-strong text-muted",
            )}
          >
            <PathIcon
              path={s.state === "done" ? ICON_PATHS.check : ICON_PATHS.close}
              size={12}
              strokeWidth={2.4}
              className={s.state === "done" ? "text-dec-allow" : "text-muted"}
            />
            {s.label}
            <span className="sr-only">: {s.state}</span>
            {s.note && <span className="text-[11.5px]">({s.note})</span>}
          </li>
        ))}
      </ol>
      {info.evaluation.length > 0 && (
        <div className="rg-scroll overflow-x-auto rounded-[6px] border border-border">
          <table aria-label="Evaluation" className="w-full min-w-[560px] border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left text-[10.5px] font-semibold uppercase tracking-[.05em] text-muted">
                <th scope="col" className="border-b border-border px-3 py-2 font-semibold">Model · held-out memos</th>
                <th scope="col" className="border-b border-border px-3 py-2 font-semibold">Quality</th>
                <th scope="col" className="border-b border-border px-3 py-2 font-semibold">Format OK</th>
                <th scope="col" className="border-b border-border px-3 py-2 font-semibold">p95 time</th>
                <th scope="col" className="border-b border-border px-3 py-2 font-semibold">Cost per memo</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {info.evaluation.map((e) => (
                <tr key={e.model} className={cn(e.current && "bg-accent-soft")}>
                  <td className="border-b border-border px-3 py-2 text-[12px]">{e.model}</td>
                  <td className="border-b border-border px-3 py-2">{e.quality}</td>
                  <td className="border-b border-border px-3 py-2">{e.formatOk}</td>
                  <td className="border-b border-border px-3 py-2">{e.p95}</td>
                  <td className="border-b border-border px-3 py-2">{e.cost}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(info.memosToday !== null || info.savedMonth !== null) && (
        <span className="text-[12.5px] text-muted">
          Since auto started using it:
          {info.memosToday !== null ? ` ${formatNumber(info.memosToday)} memos today` : ""}
          {info.savedPerMemo !== null ? `, ${info.savedPerMemo} GPU-s saved per memo` : ""}
          {info.savedMonth !== null ? `, ≈ ${formatNumber(info.savedMonth)} GPU-s this month` : ""} (shorter answers and fewer re-asks on the
          same model).
        </span>
      )}
    </section>
  );
}
