"use client";

import * as React from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import { debounce, parseAsInteger, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import {
  DataTable,
  EffectChip,
  FactsGrid,
  FilterRow,
  FilterSpacer,
  ICON_PATHS,
  ListWithSidebar,
  PageHeader,
  PathIcon,
  Pagination,
  PlainSentence,
  SearchInput,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  Truncate,
  useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { RequireRole, useHasRole } from "@/lib/auth/user-context";
import { formatWhen } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useElevations, useGrantChanges, useGrants, useRevokeGrant } from "./api";
import { useDirectory } from "./directory";
import { GrantForm, ReasonForm, type GrantFormDefaults } from "./forms";
import {
  elevationRow,
  expiresSoon,
  expiresText,
  grantRow,
  grantSentence,
  isCloudResource,
  isModelFamily,
  type DataClass,
  type GrantRowView,
} from "./model";

const VIEWS = ["active", "temp", "soon", "deny", "approval", "ended"] as const;
type View = (typeof VIEWS)[number];

const VIEW_LABEL: Record<View, string> = {
  active: "Active",
  temp: "Temporary",
  soon: "Expiring in 24 h",
  deny: "Denials",
  approval: "From approvals",
  ended: "Ended",
};

const VIEW_TEST: Record<View, (r: GrantRowView, now: number) => boolean> = {
  active: (r) => r.active,
  temp: (r) => r.active && !!r.expiresAt,
  soon: (r, now) => expiresSoon(r.expiresAt, r.active, now),
  deny: (r) => r.active && r.effect === "deny",
  approval: (r) => r.source === "elevation",
  // Not in the prototype: expired / revoked grants (history, "Grant again…").
  ended: (r) => !r.active && r.source === "grant",
};

const NO_ADMIN = "Only admins can change grants";
const NO_API = "Not available in the admin API yet";

function ExpiresCell({ row, now }: { row: GrantRowView; now: number }) {
  const soon = expiresSoon(row.expiresAt, row.active, now);
  return (
    <span className={cn("whitespace-nowrap font-mono text-[12px]", soon ? "text-dec-downgrade" : "text-muted")}>
      {row.revoked ? "revoked" : expiresText(row.expiresAt, now)}
    </span>
  );
}

export function GrantsScreen() {
  const now = Date.now();
  const isAdmin = useHasRole("admin");
  const [sel, setSel] = useSelectedId();
  const [view, setView] = useQueryState("view", parseAsStringLiteral(VIEWS).withDefault("active"));
  const [q, setQ] = useQueryState("q", parseAsString.withDefault("").withOptions({ limitUrlUpdates: debounce(300) }));
  const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
  const [size, setSize] = useQueryState("size", parseAsInteger.withDefault(25));

  const grants = useGrants();
  const elevations = useElevations();
  const { dir, subjects, groups } = useDirectory();

  /** Grants acted on in this visit stay open in the sidebar even when the filter no longer matches them. */
  const [keepId, setKeepId] = React.useState<string | null>(null);
  const [created, setCreated] = React.useState<string | null>(null);
  const [prefill, setPrefill] = React.useState<{ key: number; values?: GrantFormDefaults }>({ key: 0 });

  const allRows = React.useMemo(() => {
    const rows = (grants.data ?? []).map((g) => grantRow(g, dir));
    for (const a of elevations.data ?? []) {
      const r = elevationRow(a, dir);
      if (r) rows.push(r);
    }
    return rows.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [grants.data, elevations.data, dir]);

  const text = q.trim().toLowerCase();
  const matches = (r: GrantRowView) =>
    !text || [r.who, r.subject, r.what, r.resource, r.reason, r.id].some((v) => v.toLowerCase().includes(text));
  const counts = Object.fromEntries(VIEWS.map((v) => [v, allRows.filter((r) => VIEW_TEST[v](r, now) && matches(r)).length])) as Record<View, number>;
  const rows = allRows.filter((r) => VIEW_TEST[view](r, now) && matches(r));
  const pageCount = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(page, pageCount);
  const pageRows = rows.slice((current - 1) * size, current * size);

  const creating = sel === "new" && isAdmin;
  const selected = creating ? undefined : (rows.find((r) => r.id === sel) ?? (sel && sel === keepId ? allRows.find((r) => r.id === sel) : undefined));

  const resetPage = () => void setPage(null);

  const columns = React.useMemo<ColumnDef<GrantRowView>[]>(
    () => [
      {
        id: "who",
        header: "Who",
        meta: { className: "w-[150px] max-w-[150px] font-medium" },
        cell: ({ row }) => <Truncate>{row.original.who}</Truncate>,
      },
      {
        id: "grant",
        header: "Grant",
        meta: { className: "max-w-[260px]" },
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center gap-2">
            <EffectChip effect={row.original.effect} />
            <Truncate className="font-mono text-[12px]">{row.original.what}</Truncate>
          </span>
        ),
      },
      {
        id: "limits",
        header: "Limits",
        meta: { className: "max-w-[130px] text-muted" },
        cell: ({ row }) => <Truncate>{row.original.limits}</Truncate>,
      },
      { id: "expires", header: "Expires", meta: { className: "w-[110px]" }, cell: ({ row }) => <ExpiresCell row={row.original} now={now} /> },
      {
        id: "reason",
        header: "Reason",
        meta: { className: "max-w-[200px] text-muted" },
        cell: ({ row }) => <Truncate>{row.original.reason}</Truncate>,
      },
      { id: "go", header: "", meta: { className: "w-4 text-muted" }, cell: () => <span aria-hidden>›</span> },
    ],
    [now],
  );

  const closeSidebar = () => void setSel(null);

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader
        title="Grants"
        subtitle="personal and temporary access on top of group rules"
        actions={
          <RequireRole
            min="admin"
            fallback={
              <Button variant="primary" size="lg" disabled title={NO_ADMIN}>
                + New grant
              </Button>
            }
          >
            <Button
              variant="primary"
              size="lg"
              onClick={() => {
                setPrefill((p) => ({ key: p.key + 1 }));
                void setSel("new");
              }}
            >
              + New grant
            </Button>
          </RequireRole>
        }
      />

      <FilterRow>
        <div role="group" aria-label="Quick filters" className="flex flex-wrap gap-2">
          {VIEWS.map((v) => {
            const on = view === v;
            return (
              <button
                key={v}
                type="button"
                aria-pressed={on}
                onClick={() => {
                  void setView(v === "active" ? null : v);
                  resetPage();
                }}
                className={cn(
                  "min-h-8 rounded-full border px-3 text-[12.5px]",
                  on ? "border-accent bg-accent-soft text-text" : "border-border bg-surface text-muted hover:text-text",
                )}
              >
                {VIEW_LABEL[v]} <span className="font-mono text-muted">{counts[v]}</span>
              </button>
            );
          })}
        </div>
        <FilterSpacer />
        <SearchInput
          value={q}
          onChange={(v) => {
            void setQ(v || null);
            resetPage();
          }}
          placeholder="Person, model, tool…"
          ariaLabel="Search grants"
        />
      </FilterRow>

      <ListWithSidebar
        open={creating || !!selected}
        onClose={closeSidebar}
        sidebarLabel={creating ? "New grant" : "Grant"}
        list={
          <>
            <DataTable
              ariaLabel="Grants"
              data={pageRows}
              columns={columns}
              getRowId={(r) => r.id}
              selectedId={selected?.id ?? null}
              onRowClick={(r) => void setSel(r.id)}
              keyboardNav
              minWidth={700}
              loading={grants.isPending}
              error={grants.error}
              onRetry={() => void grants.refetch()}
              emptyTitle="No grants match"
              emptyMessage="Try another quick filter or clear the search."
            />
            <Pagination
              page={current}
              pageCount={pageCount}
              pageSize={size}
              onPageChange={(p) => void setPage(p)}
              onPageSizeChange={(s) => {
                void setSize(s);
                resetPage();
              }}
            />
          </>
        }
        sidebar={
          creating ? (
            <>
              <div className="flex items-center gap-2 border-b border-border px-3.5 py-3">
                <h2 className="m-0 text-[14px] font-semibold">New grant</h2>
                <div className="flex-1" />
                <button
                  type="button"
                  aria-label="Close new grant"
                  onClick={closeSidebar}
                  className="inline-flex size-[30px] items-center justify-center rounded-[6px] text-muted hover:bg-raised hover:text-text"
                >
                  <PathIcon path={ICON_PATHS.close} size={15} />
                </button>
              </div>
              <div className="p-3.5">
                <GrantForm
                  key={prefill.key}
                  variant="full"
                  subjects={subjects}
                  defaults={prefill.values}
                  onCancel={closeSidebar}
                  onCreated={(g) => {
                    setCreated(g.id);
                    setKeepId(g.id);
                    void setSel(g.id);
                  }}
                />
              </div>
            </>
          ) : (
            selected && (
              <GrantSidebar
                key={selected.id}
                row={selected}
                justCreated={created === selected.id}
                groupAllows={groupAllowing(selected, dir.groupOf, groups.data ?? [])}
                onActed={() => setKeepId(selected.id)}
                onGrantAgain={() => {
                  setPrefill((p) => ({
                    key: p.key + 1,
                    values: {
                      subject: `${selected.subjectType}:${selected.subject}`,
                      resource: `${selected.resourceType}:${selected.resource}`,
                      effect: selected.effect === "deny" ? "deny" : "allow",
                      dataClasses: (selected.grant?.constraints.data_classes ?? undefined) as DataClass[] | undefined,
                    },
                  }));
                  void setSel("new");
                }}
              />
            )
          )
        }
      />
    </div>
  );
}

/** Name of the group that allows what a deny grant takes away (for the sentence), if any. */
function groupAllowing(
  r: GrantRowView,
  groupOf: Map<string, string>,
  groups: readonly { name: string; settings: { models: string[]; tools: string[] } | null }[],
): string | null {
  if (r.effect !== "deny") return null;
  const name = r.subjectType === "group" ? r.subject : groupOf.get(r.subject);
  const s = groups.find((g) => g.name === name)?.settings;
  if (!s) return null;
  const list = r.resourceType === "tool" ? s.tools : isModelFamily(r.resourceType) ? s.models : [];
  return list.includes(r.resource) ? (name ?? null) : null;
}

const OP_CLASS: Record<string, string> = { created: "text-accent", expired: "text-muted", revoked: "text-dec-block" };

function GrantSidebar({
  row,
  justCreated,
  groupAllows,
  onActed,
  onGrantAgain,
}: {
  row: GrantRowView;
  justCreated: boolean;
  groupAllows: string | null;
  onActed: () => void;
  onGrantAgain: () => void;
}) {
  const now = Date.now();
  const isAdmin = useHasRole("admin");
  const changes = useGrantChanges();
  const revoke = useRevokeGrant();
  const [revoking, setRevoking] = React.useState(false);
  const g = row.grant;
  const cloud = row.effect === "allow" && isModelFamily(row.resourceType) && isCloudResource(row.resource);
  const ended = !row.active;
  const isDeny = row.effect === "deny";

  const history: { at: string; op: string; text: string }[] =
    row.source === "elevation"
      ? [
          { at: row.createdAt, op: "created", text: `from approval ${row.id} · approved by ${row.createdBy}` },
          ...(ended && row.expiresAt ? [{ at: row.expiresAt, op: "expired", text: "automatically" }] : []),
        ]
      : (changes.data ?? [])
          .filter((c) => c.grant_id === row.id)
          .sort((a, b) => a.id - b.id)
          .map((c) => ({
            at: c.at,
            op: c.change === "create" ? "created" : c.change === "revoke" ? "revoked" : "expired",
            text: c.change === "expire" ? "automatically" : `by ${c.actor} · “${c.reason}”`,
          }));

  const personHref = row.subjectType === "group" ? `/users?tab=groups&sel=${encodeURIComponent(row.subject)}` : `/users?sel=${encodeURIComponent(row.subject)}`;

  return (
    <>
      <SidebarHeader label="Grant" title={row.id} copyText={row.id} />
      <SidebarBlock>
        {justCreated && (
          <StatusBox variant="success" title={`Grant ${row.id} created`}>
            It applies from the next request. {row.who.startsWith("group ") ? "Members’" : `${row.who}’s`} clients see the change on their next model list.
          </StatusBox>
        )}
        <PlainSentence>{grantSentence(row, { groupAllows, now })}</PlainSentence>
        <FactsGrid
          facts={[
            { label: "Who", value: row.who },
            { label: "Grant", value: `${row.effect} · ${row.what}`, mono: true },
            { label: "Limits", value: row.limits },
            { label: "Expires", value: row.revoked ? "revoked" : expiresText(row.expiresAt, now), mono: true },
            { label: "Reason", value: row.reason },
            { label: "Created", value: `${formatWhen(row.createdAt, now)} by ${row.createdBy}` },
          ]}
        />
        {cloud && (
          <div className="rounded-[6px] border border-border bg-inset px-2.5 py-2 text-[12px] text-muted">
            Ceiling: LOCK-01 keeps confidential and restricted data away from cloud models, whatever this grant says.
          </div>
        )}
      </SidebarBlock>

      <SidebarSection title="History">
        {history.length === 0 ? (
          <span className="text-muted">{changes.isPending ? "Loading…" : "No recorded changes."}</span>
        ) : (
          <ol className="m-0 flex list-none flex-col gap-1 p-0">
            {history.map((h, i) => (
              <li key={i} className="grid grid-cols-[96px_70px_minmax(0,1fr)] gap-2 py-1 text-[12.5px]">
                <span className="font-mono text-[11.5px] text-muted">{formatWhen(h.at, now)}</span>
                <span className={OP_CLASS[h.op]}>{h.op}</span>
                <span className="min-w-0">{h.text}</span>
              </li>
            ))}
          </ol>
        )}
      </SidebarSection>

      {revoke.isSuccess && (
        <div className="px-3.5 pt-3">
          <StatusBox variant="success" title={isDeny ? "Denial removed" : "Revoked"}>
            {row.id} no longer applies. {row.who.startsWith("group ") ? "Members’" : `${row.who}’s`} clients see the change on their next request.
          </StatusBox>
        </div>
      )}
      {revoking && g && !revoke.isSuccess && (
        <div className="px-3.5 pt-3">
          <ReasonForm
            title={isDeny ? `Remove the denial ${row.id}` : `Revoke ${row.id}`}
            submitLabel={isDeny ? "Remove denial" : "Revoke grant"}
            pending={revoke.isPending}
            error={revoke.error}
            onCancel={() => setRevoking(false)}
            onSubmit={(reason) => {
              onActed();
              revoke.mutate({ id: g.id, reason }, { onSuccess: () => setRevoking(false) });
            }}
          />
        </div>
      )}

      <SidebarActions className="items-center">
        {row.source === "elevation" ? (
          <>
            <span className="text-[12px] text-muted">Elevations end on their own.</span>
            <Link href={`/approvals?sel=${encodeURIComponent(row.id)}`} className="text-[12.5px] text-accent">
              Open approval →
            </Link>
          </>
        ) : ended ? (
          <Button onClick={onGrantAgain} disabled={!isAdmin} title={isAdmin ? undefined : NO_ADMIN}>
            Grant again…
          </Button>
        ) : (
          <>
            {!isDeny && (
              <Button variant="primary" disabled title={isAdmin ? NO_API : NO_ADMIN}>
                Extend…
              </Button>
            )}
            <Button disabled title={isAdmin ? NO_API : NO_ADMIN}>
              Edit…
            </Button>
            <Button
              className="text-dec-block"
              disabled={!isAdmin || revoking || revoke.isSuccess}
              title={isAdmin ? undefined : NO_ADMIN}
              onClick={() => setRevoking(true)}
            >
              {isDeny ? "Remove denial" : "Revoke"}
            </Button>
          </>
        )}
        <Link href={personHref} className="ml-auto self-center text-[12.5px] text-accent">
          {row.subjectType === "group" ? "Open group →" : "Open person →"}
        </Link>
      </SidebarActions>
    </>
  );
}
