"use client";

import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import type { UseQueryResult } from "@tanstack/react-query";
import {
  Avatar,
  DataTable,
  ICON_PATHS,
  ListWithSidebar,
  PathIcon,
  Segmented,
  StatusBox,
  ToggleChip,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useGrants } from "@/features/grants/api";
import { effectKind, isModelFamily, modelChipLabel, toolLabel } from "@/features/grants/model";
import { usePolicyStatus } from "@/lib/api/hooks";
import type { Group, GroupSettings } from "@/lib/api/types";
import { useHasRole, useUser } from "@/lib/auth/user-context";
import { formatUsd } from "@/lib/format";
import { useGroupPreview, useSaveGroupSettings, useUsers } from "./api";
import { tokensInOut } from "./format";
import { KeycloakLink } from "./keycloak";

/** Models and tools offered as toggle chips (HANDOFF 7.1 lineup, tools.yaml ids); a group's own entries are added. */
const MODEL_CHOICES = ["auto", "fast", "local", "smart", "smart-pro", "local/loan-memo"];
const TOOL_CHOICES = ["opencode.read", "opencode.edit", "opencode.write", "opencode.bash", "web.fetch", "mail.send", "bank.query"];
const PRESETS = ["monitor", "balanced", "strict", "paranoid"] as const;
const CLOUD = [
  { value: "none", label: "nothing" },
  { value: "public", label: "public" },
  { value: "internal", label: "internal" },
] as const;

export function GroupsTab({ groups, q }: { groups: UseQueryResult<Group[]>; q: string }) {
  const [sel, setSel] = useSelectedId();
  const text = q.trim().toLowerCase();
  const rows = (groups.data ?? []).filter((g) => !text || g.name.toLowerCase().includes(text));
  const selected = rows.find((g) => g.name === sel);

  const columns: ColumnDef<Group>[] = [
    { id: "name", header: "Group", meta: { className: "font-medium" }, cell: ({ row }) => row.original.name },
    {
      id: "members",
      header: "Members",
      meta: { className: "text-right font-mono text-[12px]", headerClassName: "text-right" },
      cell: ({ row }) => row.original.members,
    },
    { id: "preset", header: "Preset", meta: { className: "text-muted" }, cell: ({ row }) => row.original.preset ?? "—" },
    {
      id: "models",
      header: "Models",
      meta: { className: "max-w-[240px] font-mono text-[12px]" },
      cell: ({ row }) => <Truncate>{row.original.settings?.models.join(" · ") || "—"}</Truncate>,
    },
    {
      id: "tokens",
      header: "Tokens in / out today",
      meta: { className: "text-right font-mono text-[12px] whitespace-nowrap", headerClassName: "text-right" },
      cell: ({ row }) => tokensInOut(row.original.stats_today?.tokens_in ?? 0, row.original.stats_today?.tokens_out ?? 0),
    },
    {
      id: "spend",
      header: "Spend today",
      meta: { className: "text-right font-mono text-[12px] whitespace-nowrap", headerClassName: "text-right" },
      cell: ({ row }) => `${formatUsd(row.original.stats_today?.usd ?? 0)} USD`,
    },
    { id: "go", header: "", meta: { className: "w-4 text-muted" }, cell: () => <span aria-hidden>›</span> },
  ];

  return (
    <ListWithSidebar
      open={!!selected}
      onClose={() => void setSel(null)}
      sidebarLabel="Group"
      list={
        <DataTable
          ariaLabel="Groups"
          data={rows}
          columns={columns}
          getRowId={(g) => g.name}
          selectedId={selected?.name ?? null}
          onRowClick={(g) => void setSel(g.name)}
          keyboardNav
          minWidth={680}
          loading={groups.isPending}
          error={groups.error}
          onRetry={() => void groups.refetch()}
          emptyTitle="No groups match"
        />
      }
      sidebar={selected && <GroupSidebar key={selected.name} group={selected} onClose={() => void setSel(null)} />}
    />
  );
}

const EMPTY: GroupSettings = { preset: null, models: [], tools: [], max_cloud_data_class: "internal", daily_budget_usd: null };

const sameSettings = (a: GroupSettings, b: GroupSettings) =>
  a.preset === b.preset &&
  a.max_cloud_data_class === b.max_cloud_data_class &&
  (a.daily_budget_usd ?? null) === (b.daily_budget_usd ?? null) &&
  a.models.length === b.models.length &&
  a.models.every((m) => b.models.includes(m)) &&
  a.tools.length === b.tools.length &&
  a.tools.every((t) => b.tools.includes(t));

/** Gateway change strings → the panel's short wording ("+ model smart" → "+ smart (gemini)"). */
export function prettyChange(c: string): string {
  let m = /^([+-]) model (.+)$/.exec(c);
  if (m) return `${m[1] === "+" ? "+" : "−"} ${modelChipLabel(m[2])}`;
  m = /^([+-]) tool (.+)$/.exec(c);
  if (m) return `${m[1] === "+" ? "+" : "−"} ${toolLabel(m[2])}`;
  m = /^daily budget (.+)$/.exec(c);
  if (m) return `budget ${m[1]}`;
  return c;
}

function GroupSidebar({ group, onClose }: { group: Group; onClose: () => void }) {
  const isAdmin = useHasRole("admin");
  const base = group.settings ?? EMPTY;
  const [draft, setDraft] = React.useState<GroupSettings>(base);
  const [saved, setSaved] = React.useState<{ version: string; settings: GroupSettings } | null>(null);
  const policy = usePolicyStatus();
  const dirty = !!group.settings && !sameSettings(draft, base);
  const justSaved = !!saved && sameSettings(saved.settings, draft);
  const preview = useGroupPreview(group.name, draft, policy.data?.version, dirty && isAdmin && !justSaved);
  const save = useSaveGroupSettings();

  const edit = (patch: Partial<GroupSettings>) => {
    setSaved(null);
    save.reset();
    setDraft((d) => ({ ...d, ...patch }));
  };
  const toggle = (key: "models" | "tools", id: string, on: boolean) =>
    edit({ [key]: on ? [...draft[key], id] : draft[key].filter((x) => x !== id) });

  const models = [...new Set([...MODEL_CHOICES, ...base.models, ...draft.models])];
  const tools = [...new Set([...TOOL_CHOICES, ...base.tools, ...draft.tools])];
  const budget = draft.daily_budget_usd ?? 0;
  const p = preview.data;
  const changes = p?.changes.map(prettyChange) ?? [];
  const summary =
    p && p.valid
      ? `${changes.length} ${changes.length === 1 ? "change" : "changes"}: ${changes.join(", ")} · written to ${p.files_changed.join(", ") || "groups.yaml"}`
      : "Checking the change…";
  const canSave = isAdmin && !!p?.valid && changes.length > 0 && !preview.isFetching && !save.isPending && !!policy.data;

  return (
    <>
      <div className="flex items-center gap-2.5 border-b border-border p-3.5">
        <span className="flex min-w-0 flex-1 flex-col">
          <b className="text-[15px] font-semibold">{group.name}</b>
          <span className="text-[12px] text-muted">
            Keycloak group · <span className="font-mono">{group.members}</span> members ·{" "}
            <span className="font-mono">{tokensInOut(group.stats_today?.tokens_in ?? 0, group.stats_today?.tokens_out ?? 0)}</span> tokens today
          </span>
        </span>
        <button
          type="button"
          aria-label="Close group"
          onClick={onClose}
          className="inline-flex size-[30px] items-center justify-center rounded-[6px] text-muted hover:bg-raised hover:text-text"
        >
          <PathIcon path={ICON_PATHS.close} size={15} />
        </button>
      </div>
      <div className="border-b border-border px-3.5 py-2.5 text-[12px] text-muted">
        Who is in the group comes from Keycloak. What the group may use is set here and saved to <span className="font-mono">groups.yaml</span> as a
        new policy version.
        {!isAdmin && " Only admins can change it."}
      </div>

      {group.settings ? (
        <fieldset disabled={!isAdmin} aria-label="Group settings" className="m-0 flex min-w-0 flex-col gap-3.5 border-0 border-b border-border p-3.5">
          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold">Strictness</span>
            <Segmented
              ariaLabel="Strictness"
              className="self-start"
              value={draft.preset ?? "balanced"}
              onChange={(v) => edit({ preset: v })}
              options={PRESETS.map((x) => ({ value: x, label: x }))}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold">
              Models <span className="font-normal text-muted">· click to allow or remove</span>
            </span>
            <div role="group" aria-label="Models" className="flex flex-wrap gap-1.5">
              {models.map((m) => (
                <ToggleChip key={m} label={modelChipLabel(m)} on={draft.models.includes(m)} disabled={!isAdmin} onChange={(on) => toggle("models", m, on)} className="font-mono text-[12px]" />
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold">Tools</span>
            <div role="group" aria-label="Tools" className="flex flex-wrap gap-1.5">
              {tools.map((t) => (
                <ToggleChip key={t} label={toolLabel(t)} on={draft.tools.includes(t)} disabled={!isAdmin} onChange={(on) => toggle("tools", t, on)} className="font-mono text-[12px]" />
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-x-7 gap-y-3.5">
            <div className="flex flex-col gap-1.5">
              <span className="text-[12px] font-semibold">Cloud models may get</span>
              <Segmented
                ariaLabel="Cloud models may get"
                className="self-start"
                value={draft.max_cloud_data_class}
                onChange={(v) => edit({ max_cloud_data_class: v })}
                options={CLOUD}
              />
              <span className="text-[12px] text-muted">confidential and above: never (LOCK-01)</span>
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-[12px] font-semibold">Daily budget</span>
              <span className="inline-flex self-start overflow-hidden rounded-[6px] border border-border-strong">
                <button
                  type="button"
                  aria-label="Lower budget"
                  disabled={budget <= 0}
                  onClick={() => edit({ daily_budget_usd: Math.max(0, budget - 1) })}
                  className="w-8 border-0 border-r border-border bg-raised text-text disabled:opacity-50"
                >
                  −
                </button>
                <span aria-label="Daily budget" className="inline-flex min-h-8 items-center px-3 font-mono font-semibold">
                  {formatUsd(budget)} USD
                </span>
                <button
                  type="button"
                  aria-label="Raise budget"
                  disabled={budget >= 50}
                  onClick={() => edit({ daily_budget_usd: Math.min(50, budget + 1) })}
                  className="w-8 border-0 border-l border-border bg-raised text-text disabled:opacity-50"
                >
                  +
                </button>
              </span>
              <span className="text-[12px] text-muted">used today {formatUsd(group.stats_today?.usd ?? 0)} USD</span>
            </div>
          </div>

          {dirty && !justSaved && (
            <div
              role="region"
              aria-label="Unsaved changes"
              className="flex flex-wrap items-center gap-2 rounded-[8px] border border-accent-line bg-inset px-3 py-2.5"
            >
              <span className="min-w-[200px] flex-1 text-[13px]">{summary}</span>
              <Button variant="ghost" className="border-border" onClick={() => setDraft(base)}>
                Discard
              </Button>
              <Button
                variant="primary"
                disabled={!canSave}
                onClick={() =>
                  save.mutate(
                    { name: group.name, settings: draft, baseVersion: policy.data!.version },
                    { onSuccess: (status) => setSaved({ version: status.version, settings: draft }) },
                  )
                }
              >
                Save as policy {p?.candidate_version ?? "…"}
              </Button>
            </div>
          )}
          {p && !p.valid && dirty && (
            <StatusBox variant="error" title="This change is not valid">
              {p.errors.map((e) => e.message).join(" ")}
            </StatusBox>
          )}
          {preview.isError && (
            <StatusBox variant="error" title="Could not check the change">
              {preview.error.message}
            </StatusBox>
          )}
          {save.isError && (
            <StatusBox variant="error" title="Could not save">
              {save.error.message}
            </StatusBox>
          )}
          {justSaved && saved && (
            <StatusBox variant="success" title={`${saved.version} is live.`}>
              Saved as policy {saved.version}. Members’ clients get the new model and tool lists on their next request.
            </StatusBox>
          )}
        </fieldset>
      ) : (
        <div className="border-b border-border p-3.5 text-[13px] text-muted">This group exists only in Keycloak; it has no settings in groups.yaml yet.</div>
      )}

      <Members group={group} />
    </>
  );
}

function Members({ group }: { group: Group }) {
  const users = useUsers();
  const grants = useGrants();
  const me = useUser();
  const members = (users.data ?? []).filter((u) => u.kind === "user" && u.groups.includes(group.name));
  const shown = members.slice(0, 3);
  const rest = group.members - shown.length;
  const noteFor = (username: string) => {
    if (username === me.username) return "you";
    const g = (grants.data ?? []).find((x) => x.active && x.subject_type === "user" && x.subject === username && effectKind(x) !== "budget");
    if (!g) return "";
    return g.effect === "deny" ? `denied: ${toolLabel(g.resource)}` : `personal grant: ${isModelFamily(g.resource_type) ? g.resource : toolLabel(g.resource)}`;
  };
  return (
    <section aria-labelledby="members-h" className="flex flex-col gap-1.5 p-3.5">
      <div className="flex items-baseline gap-2">
        <h3 id="members-h" className="m-0 text-[12px] font-semibold">
          Members
        </h3>
        <span className="font-mono text-[12px] text-muted">{group.members}</span>
        <div className="ml-auto">
          <KeycloakLink label="Manage in Keycloak" />
        </div>
      </div>
      <ul aria-label="Members" className="m-0 flex list-none flex-col p-0">
        {shown.map((u) => (
          <li key={u.username} className="flex items-center gap-2 py-1 text-[13px]">
            <Avatar name={u.display_name ?? u.username} size={24} />
            <span className="flex-1">{u.display_name ?? u.username}</span>
            <span className="text-[12px] text-muted">{noteFor(u.username)}</span>
          </li>
        ))}
        {rest > 0 && (
          <li className="flex items-center gap-2 py-1 text-[13px] text-muted">
            <span className="inline-flex size-6 items-center justify-center rounded-full bg-accent-soft text-[10px] font-semibold text-text">+</span>
            {rest} more
          </li>
        )}
      </ul>
    </section>
  );
}
