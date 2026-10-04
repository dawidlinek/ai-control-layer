"use client";

import * as React from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import type { ListQuery } from "@/lib/api/hooks";
import { parseAsInteger, useQueryState } from "nuqs";
import {
  Avatar,
  DataTable,
  DecisionBadge,
  ICON_PATHS,
  ListWithSidebar,
  Pagination,
  PathIcon,
  SidebarSection,
  StatusBox,
  Truncate,
  useSelectedId,
  linkClass,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useElevations, useGrants, useRevokeGrant, useCreateGrant } from "@/features/grants/api";
import { GrantForm, ReasonForm } from "@/features/grants/forms";
import { expiresSoon, expiresText, isModelFamily, itemLabel, RESOURCE_OPTIONS } from "@/features/grants/model";
import type { Group, User } from "@/lib/api/types";
import { useHasRole } from "@/lib/auth/user-context";
import { DECISION_ICON, DECISION_TEXT_CLASS } from "@/lib/decisions";
import { formatNumber, formatTime, formatWhen } from "@/lib/format";
import { cn } from "@/lib/utils";
import { buildAccessRows, clientModels, type AccessAction, type AccessRow, type AccessState } from "./access";
import { useEffectiveAccess, useUserActivity } from "./api";
import { firstName, lastActiveLabel, tokensInOut } from "./format";

export function PeopleTab({
  users,
  groups,
  q,
  group,
  risk,
}: {
  users: ListQuery<User>;
  groups: readonly Group[];
  q: string;
  group: string | null;
  risk: "blocks" | null;
}) {
  const [sel, setSel] = useSelectedId();
  const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
  const [size, setSize] = useQueryState("size", parseAsInteger.withDefault(25));
  const text = q.trim().toLowerCase();
  const rows = (users.data ?? [])
    .filter((u) => u.kind === "user")
    .filter((u) => (group ? u.groups.includes(group) : true))
    .filter((u) => (risk === "blocks" ? (u.stats_7d?.blocks ?? 0) > 0 : true))
    .filter((u) => !text || [u.username, u.display_name, u.email].some((v) => v?.toLowerCase().includes(text)));
  const pageCount = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(page, pageCount);
  const pageRows = rows.slice((current - 1) * size, current * size);
  const selected = rows.find((u) => u.username === sel);
  const now = Date.now();

  const columns: ColumnDef<User>[] = [
    {
      id: "person",
      header: "Person",
      meta: { className: "max-w-[260px]" },
      cell: ({ row }) => {
        const u = row.original;
        return (
          <span className="flex min-w-0 items-center gap-2.5">
            <Avatar name={u.display_name ?? u.username} size={28} />
            <span className="flex min-w-0 flex-col leading-[1.3]">
              <Truncate className="font-medium">{u.display_name ?? u.username}</Truncate>
              <Truncate className="text-[12px] text-muted">{u.email ?? u.username}</Truncate>
            </span>
          </span>
        );
      },
    },
    { id: "group", header: "Group", cell: ({ row }) => row.original.groups.join(", ") || "—" },
    { id: "preset", header: "Preset", meta: { className: "text-muted" }, cell: ({ row }) => row.original.preset ?? "—" },
    {
      id: "last",
      header: "Last active",
      meta: { className: "font-mono text-[12px]" },
      cell: ({ row }) => {
        const iso = row.original.stats_7d?.last_active ?? row.original.last_seen;
        return <time dateTime={iso ?? undefined}>{lastActiveLabel(iso, now)}</time>;
      },
    },
    {
      id: "requests",
      header: "Requests 7 d",
      meta: { className: "text-right font-mono text-[12px]", headerClassName: "text-right" },
      cell: ({ row }) => formatNumber(row.original.stats_7d?.requests ?? 0),
    },
    {
      id: "tokens",
      header: "Tokens in / out 7 d",
      meta: { className: "text-right font-mono text-[12px] whitespace-nowrap", headerClassName: "text-right" },
      cell: ({ row }) => tokensInOut(row.original.stats_7d?.tokens_in ?? 0, row.original.stats_7d?.tokens_out ?? 0),
    },
    {
      id: "blocks",
      header: "Blocks",
      meta: { className: "text-right font-mono text-[12px]", headerClassName: "text-right" },
      cell: ({ row }) => {
        const b = row.original.stats_7d?.blocks ?? 0;
        return <span className={b > 0 ? "text-dec-block" : "text-muted"}>{b}</span>;
      },
    },
    { id: "go", header: "", meta: { className: "w-4 text-muted" }, cell: () => <span aria-hidden>›</span> },
  ];

  return (
    <ListWithSidebar
      open={!!selected}
      onClose={() => void setSel(null)}
      sidebarLabel="Person"
      list={
        <>
          <DataTable
            ariaLabel="People"
            data={pageRows}
            columns={columns}
            getRowId={(u) => u.username}
            selectedId={selected?.username ?? null}
            onRowClick={(u) => void setSel(u.username)}
            keyboardNav
            loading={users.isPending}
            error={users.error}
            onRetry={() => void users.refetch()}
            emptyTitle="Nobody matches"
            emptyMessage="Clear the filters or the search."
          />
          <Pagination
            page={current}
            pageCount={pageCount}
            pageSize={size}
            onPageChange={(p) => void setPage(p)}
            onPageSizeChange={(s) => {
              void setSize(s);
              void setPage(null);
            }}
          />
        </>
      }
      sidebar={selected && <PersonSidebar key={selected.username} user={selected} group={groups.find((g) => selected.groups.includes(g.name))} onClose={() => void setSel(null)} />}
    />
  );
}

const STATE_ICON: Record<AccessState, { path: string; className: string; label: string }> = {
  ok: { path: DECISION_ICON.allow, className: DECISION_TEXT_CLASS.allow, label: "allowed" },
  no: { path: DECISION_ICON.block, className: DECISION_TEXT_CLASS.block, label: "denied" },
  elevated: { path: DECISION_ICON.require_approval, className: DECISION_TEXT_CLASS.require_approval, label: "elevated" },
  none: { path: "M6 12h12", className: "text-muted", label: "not granted" },
  value: { path: "M5 12h14", className: "text-muted", label: "limit" },
};

type Result = { variant: "success" | "error"; title: string; body: string };

function PersonSidebar({ user, group, onClose }: { user: User; group: Group | undefined; onClose: () => void }) {
  const isAdmin = useHasRole("admin");
  const name = user.display_name ?? user.username;
  const first = firstName(name);
  const access = useEffectiveAccess(user.username);
  const activity = useUserActivity(user.username, 4);
  const grants = useGrants();
  const elevations = useElevations();
  const revoke = useRevokeGrant();
  const deny = useCreateGrant();
  const [pending, setPending] = React.useState<{ action: AccessAction | { type: "new" }; item: string } | null>(null);
  const [fresh, setFresh] = React.useState<ReadonlySet<string>>(new Set());
  const [freshModels, setFreshModels] = React.useState<ReadonlySet<string>>(new Set());
  const [result, setResult] = React.useState<Result | null>(null);
  const stats = user.stats_7d;

  const myGrants = (grants.data ?? []).filter((g) => g.subject === user.username || g.subject === user.subject);
  const myElevations = (elevations.data ?? []).filter((a) => a.requested_by === user.username);
  const rows = access.data
    ? buildAccessRows({ access: access.data, grants: grants.data ?? [], group, elevations: myElevations, fresh })
    : [];
  const models = access.data ? clientModels(access.data) : [];
  const allowed = new Set(models.map((m) => m.id));
  const grantOptions = RESOURCE_OPTIONS.filter((o) => isModelFamily(o.type) && !allowed.has(o.resource));

  const start = (action: AccessAction | { type: "new" }, item = "") => {
    setResult(null);
    revoke.reset();
    deny.reset();
    setPending({ action, item });
  };
  const act = pending?.action;

  return (
    <>
      <div className="flex items-start gap-2.5 border-b border-border p-3.5">
        <Avatar name={name} size={40} />
        <span className="flex min-w-0 flex-1 flex-col gap-0.5">
          <b className="text-[15px] font-semibold">{name}</b>
          <span className="truncate text-[12px] text-muted">
            {[user.email ?? user.username, user.groups.join(", ") || "no group", user.preset ?? "—"].join(" · ")}
          </span>
          <span className="text-[12px] text-muted">
            7 days:{" "}
            <span className="font-mono text-text">
              {formatNumber(stats?.requests ?? 0)} requests · {tokensInOut(stats?.tokens_in ?? 0, stats?.tokens_out ?? 0)} tokens in / out
            </span>
          </span>
        </span>
        <button
          type="button"
          aria-label="Close person"
          onClick={onClose}
          className="inline-flex size-[30px] items-center justify-center rounded-[6px] text-muted hover:bg-raised hover:text-text"
        >
          <PathIcon path={ICON_PATHS.close} size={15} />
        </button>
      </div>

      <section aria-labelledby="access-h" className="flex flex-col gap-1 border-b border-border p-3.5">
        <div className="mb-1 flex items-baseline gap-2">
          <h3 id="access-h" className="m-0 text-[12px] font-semibold">
            Access
          </h3>
          <span className="text-[12px] text-muted">and where it comes from</span>
          <div className="flex-1" />
          {isAdmin ? (
            <Button size="sm" variant="ghost" disabled={grantOptions.length === 0} onClick={() => start({ type: "new" })}>
              + Grant
            </Button>
          ) : (
            <Button size="sm" variant="ghost" disabled title="Only admins can grant access">
              + Grant
            </Button>
          )}
        </div>
        {access.isPending && <span className="py-2 text-muted">Loading access…</span>}
        {access.isError && (
          <StatusBox variant="error" title="Could not load access">
            {access.error.message}
          </StatusBox>
        )}
        <ul aria-label="Access" className="m-0 flex list-none flex-col p-0">
          {rows.map((r) => (
            <AccessLine key={r.key} row={r} canAct={isAdmin} onAction={(a) => start(a, r.item)} />
          ))}
        </ul>

        {act && (act.type === "new" || act.type === "grant") && (
          <GrantForm
            variant="person"
            personName={first}
            resourceOptions={act.type === "grant" ? grantOptions.filter((o) => o.resource === act.resource) : grantOptions}
            defaults={{ subject: `user:${user.username}`, resource: act.type === "grant" ? `${act.resourceType}:${act.resource}` : grantOptions[0]?.value }}
            onCancel={() => setPending(null)}
            onCreated={(g) => {
              setPending(null);
              setFresh((s) => new Set(s).add(g.id));
              setFreshModels((s) => new Set(s).add(g.resource));
              setResult({
                variant: "success",
                title: `${first} can use ${itemLabel(g.resource_type, g.resource)}${g.expires_at ? ` until ${formatWhen(g.expires_at)}` : ""}`,
                body: `Saved as grant ${g.id}. Their clients get the new model on their next request.`,
              });
            }}
          />
        )}
        {pending && act && act.type !== "new" && act.type !== "grant" && (
          <div className="mt-1">
            <ReasonForm
              title={
                act.type === "deny"
                  ? `Take ${pending.item} away from ${first} (overrides group ${group?.name ?? ""})`
                  : act.type === "restore"
                    ? `Restore ${pending.item} for ${first} (removes ${act.grantId})`
                    : `Revoke ${act.grantId} (${pending.item})`
              }
              submitLabel={act.type === "deny" ? `Deny ${pending.item}` : act.type === "restore" ? "Restore" : "Revoke grant"}
              danger={act.type !== "restore"}
              pending={revoke.isPending || deny.isPending}
              error={revoke.error ?? deny.error}
              onCancel={() => setPending(null)}
              onSubmit={(reason) => {
                const item = pending.item;
                if (act.type === "deny") {
                  deny.mutate(
                    { subject_type: "user", subject: user.username, resource_type: act.resourceType, resource: act.resource, effect: "deny", constraints: {}, expires_at: null, reason },
                    {
                      onSuccess: (g) => {
                        setPending(null);
                        setFresh((s) => new Set(s).add(g.id));
                        setResult({ variant: "success", title: `${item} denied for ${first}`, body: `Saved as grant ${g.id}. It overrides the group from the next request.` });
                      },
                    },
                  );
                } else {
                  revoke.mutate(
                    { id: act.grantId, reason },
                    {
                      onSuccess: () => {
                        setPending(null);
                        setResult(
                          act.type === "restore"
                            ? { variant: "success", title: `${item} restored for ${first}`, body: `${act.grantId} was removed; the group rule applies again.` }
                            : { variant: "success", title: `Revoked ${act.grantId}`, body: `${first}’s clients lose ${item} on their next request.` },
                        );
                      },
                    },
                  );
                }
              }}
            />
          </div>
        )}
        {result && (
          <div className="mt-2">
            <StatusBox variant={result.variant} title={result.title}>
              {result.body}
            </StatusBox>
          </div>
        )}
      </section>

      <SidebarSection title="Their clients see">
        <ul aria-label="Their clients see" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {models.map((m) => {
            const isNew = freshModels.has(m.id);
            return (
              <li
                key={m.id}
                className={cn(
                  "rounded-[4px] border px-1.5 font-mono text-[12px] leading-[1.6]",
                  isNew ? "border-accent-line bg-accent-soft" : "border-border",
                )}
              >
                {m.id}
                {isNew && " (new)"}
              </li>
            );
          })}
          {access.data && models.length === 0 && <li className="text-muted">No models</li>}
        </ul>
      </SidebarSection>

      <SidebarSection title="Recent activity" className="border-b-0">
        {activity.isPending && <span className="text-muted">Loading…</span>}
        {activity.data?.length === 0 && <span className="text-muted">No requests yet.</span>}
        <ul aria-label="Recent activity" className="m-0 flex list-none flex-col p-0">
          {(activity.data ?? []).slice(0, 4).map((e) => (
            <li key={e.event_id}>
              <Link
                href={`/traffic?sel=${encodeURIComponent(e.trace_id ?? e.event_id)}`}
                className="grid grid-cols-[64px_minmax(0,1fr)_auto] items-center gap-2 rounded-[4px] py-1.5 text-[13px] text-text no-underline hover:bg-raised"
              >
                <span className="font-mono text-[12px] text-muted">{formatTime(e.timestamp)}</span>
                <span className="truncate font-mono text-[12px]">{e.tool ?? e.model ?? e.point ?? e.event_type}</span>
                {e.action ? <DecisionBadge decision={e.action} /> : <span />}
              </Link>
            </li>
          ))}
        </ul>
        <div className="mt-1 flex flex-wrap gap-4 text-[13px]">
          <Link href={`/traffic?q=${encodeURIComponent(user.username)}`} className={linkClass}>
            All activity in Traffic →
          </Link>
          <Link href={`/grants?q=${encodeURIComponent(user.username)}`} className={linkClass}>
            Grant history →
          </Link>
          {myGrants.length > 0 && <span className="text-muted">{myGrants.length} grants on record</span>}
        </div>
      </SidebarSection>
    </>
  );
}

function AccessLine({ row, canAct, onAction }: { row: AccessRow; canAct: boolean; onAction: (a: AccessAction) => void }) {
  const icon = STATE_ICON[row.state];
  const now = Date.now();
  const soon = row.state === "elevated" || expiresSoon(row.expiresAt, true, now);
  return (
    <li
      data-access={row.key}
      className={cn(
        "grid grid-cols-[56px_minmax(0,1fr)_auto_auto] items-center gap-2 rounded-[6px] px-1.5 py-1.5 text-[13px]",
        row.fresh && "bg-accent-soft",
      )}
    >
      <span className="text-[12px] text-muted">{row.kind}</span>
      <span className="flex min-w-0 flex-col">
        <span className="flex min-w-0 items-center gap-1.5">
          <PathIcon path={icon.path} size={12} strokeWidth={2.4} className={cn("shrink-0", icon.className)} aria-hidden={false} role="img" aria-label={icon.label} />
          <span className="truncate font-mono text-[12px]">{row.item}</span>
        </span>
        <span className="truncate text-[12px] text-muted">{row.source}</span>
      </span>
      <span className={cn("whitespace-nowrap font-mono text-[12px]", soon ? "text-dec-downgrade" : "text-muted")}>
        {row.expiresAt ? expiresText(row.expiresAt, now) : ""}
      </span>
      <span>
        {canAct && row.action && (
          <Button size="sm" variant="ghost" className={cn("min-h-7 px-2", row.action.type === "grant" || row.action.type === "restore" ? "text-text" : "text-dec-block")} onClick={() => onAction(row.action!)} aria-label={`${actionLabel(row.action)} ${row.item}`}>
            {actionLabel(row.action)}
          </Button>
        )}
      </span>
    </li>
  );
}

const actionLabel = (a: AccessAction) => (a.type === "grant" ? "Grant" : a.label);
