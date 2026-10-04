"use client";

import * as React from "react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  DiffBox,
  FactsGrid,
  PlainSentence,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  ToolStatusChip,
  linkClass,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Label, Textarea } from "@/components/ui/input";
import { useHasRole } from "@/lib/auth/user-context";
import { formatWhen } from "@/lib/format";
import { useApproveTool, useQuarantineTool } from "./api";
import { aboutOf, parseDiff, shortHash, type ToolRow } from "./catalogue";

type Action = "approve" | "quarantine";

const reasonSchema = z.object({ reason: z.string().trim().min(1, "Write a reason. It is saved in the audit log.") });
type ReasonForm = z.infer<typeof reasonSchema>;

function ApprovedVersions({ row, justApproved }: { row: ToolRow; justApproved: boolean }) {
  const t = row.mcp;
  if (!t) return null;
  const items: Array<{ hash: string; when: string; what: string }> = [];
  if (t.pinned_hash) {
    const by = row.details.approvedBy ? ` by ${row.details.approvedBy}` : "";
    items.push({
      hash: shortHash(t.pinned_hash),
      when: justApproved ? "just now" : t.first_seen ? formatWhen(t.first_seen) : "—",
      what: justApproved ? "approved version (re-approved)" : `approved version${by}`,
    });
  }
  if (t.current_hash && t.current_hash !== t.pinned_hash) {
    items.push({
      hash: shortHash(t.current_hash),
      when: t.drift_detected_at ? formatWhen(t.drift_detected_at) : "—",
      what: "changed · not approved",
    });
  }
  return (
    <SidebarSection title="Approved versions">
      {items.length ? (
        <ul aria-label="Approved versions" className="m-0 flex list-none flex-col gap-1 p-0">
          {items.map((p) => (
            <li key={p.hash + p.what} className="grid grid-cols-[110px_110px_minmax(0,1fr)] gap-2 py-0.5 text-[13px]">
              <span className="font-mono text-[12px]">{p.hash}</span>
              <span className="text-muted">{p.when}</span>
              <span>{p.what}</span>
            </li>
          ))}
        </ul>
      ) : (
        <span className="text-[13px] text-muted">No version approved yet.</span>
      )}
    </SidebarSection>
  );
}

function ChangedSinceApproval({ row }: { row: ToolRow }) {
  const lines = parseDiff(row.mcp?.description_diff);
  if (!lines.length) return null;
  const inc = row.details.incident;
  return (
    <SidebarSection
      title="Changed since approval"
      aside={
        inc ? (
          <Link href={`/incidents?sel=${inc}`} className={`${linkClass} text-[13px]`}>
            {inc} →
          </Link>
        ) : undefined
      }
    >
      <DiffBox lines={lines} addedTone="bad" removedTone="good" ariaLabel="Description diff" />
    </SidebarSection>
  );
}

export function ToolSidebar({ row, calls }: { row: ToolRow; calls: number | undefined }) {
  const isAdmin = useHasRole("admin");
  const isAnalyst = useHasRole("analyst");
  const approve = useApproveTool();
  const quarantine = useQuarantineTool();
  const [action, setAction] = React.useState<Action | null>(null);
  const [wasQuarantined, setWasQuarantined] = React.useState(false);
  const form = useForm<ReasonForm>({ resolver: zodResolver(reasonSchema), defaultValues: { reason: "" } });
  const error = form.formState.errors.reason?.message;
  const pending = approve.isPending || quarantine.isPending;

  const t = row.mcp;
  const isMcp = row.kind === "mcp" && !!t;
  const quarantined = row.status === "quarantined";

  function start(a: Action) {
    approve.reset();
    quarantine.reset();
    setAction(a);
  }

  const submit = form.handleSubmit((v) => {
    if (!t) return;
    const reason = v.reason.trim();
    if (action === "approve") {
      approve.mutate({ id: t.id, reason }, { onSuccess: () => setAction(null) });
    } else {
      setWasQuarantined(quarantined);
      quarantine.mutate({ id: t.id, reason }, { onSuccess: () => setAction(null) });
    }
  });

  const facts: Array<{ label: string; value: React.ReactNode; mono?: boolean }> = [];
  if (isMcp && t) {
    const s = row.serverInfo;
    facts.push({ label: "Server", value: s ? `${s.id} (${s.transport === "stdio" ? "local" : "remote"}, ${s.status})` : t.server });
    facts.push({ label: "Rule", value: row.rule });
    for (const [label, value] of row.details.facts ?? []) facts.push({ label, value });
    if (t.drift_detected_at) facts.push({ label: "Changed", value: formatWhen(t.drift_detected_at), mono: true });
    else if (t.first_seen) facts.push({ label: "First seen", value: formatWhen(t.first_seen), mono: true });
  } else {
    for (const [label, value] of row.details.facts ?? []) facts.push({ label, value });
  }
  facts.push({ label: "Calls 24 h", value: calls === undefined ? "—" : String(calls), mono: true });

  const approveLabel = quarantined ? "Re-approve new version…" : "Approve…";
  const quarantineLabel = quarantined ? "Keep quarantined…" : "Quarantine…";
  const adminOnly = "Only admins can approve tools";
  const analystOnly = "Only analysts and admins can quarantine tools";

  return (
    <>
      <SidebarHeader label="Tool" title={row.id} copyText={row.id} actions={<ToolStatusChip status={row.status} />} />
      <SidebarBlock>
        <PlainSentence>{aboutOf(row)}</PlainSentence>
        <FactsGrid facts={facts.slice(0, 8)} />
        {row.labels.length > 0 && (
          <ul aria-label="Labels" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
            {row.labels.map((l) => (
              <li key={l} className="rounded-full border border-border px-2 py-px text-[12px] text-muted">
                {l}
              </li>
            ))}
          </ul>
        )}
      </SidebarBlock>
      <ChangedSinceApproval row={row} />
      {isMcp && <ApprovedVersions row={row} justApproved={approve.isSuccess} />}

      {approve.isSuccess && (
        <div className="px-3.5 pt-3">
          <StatusBox variant="success" title="New version approved">
            {row.id} is back in agents’ tool lists on their next refresh. Approved hash{" "}
            <span className="font-mono">{shortHash(approve.data.pinned_hash)}</span>.
          </StatusBox>
        </div>
      )}
      {quarantine.isSuccess && (
        <div className="px-3.5 pt-3">
          <StatusBox variant="success" title={wasQuarantined ? "Kept quarantined" : "Quarantined"}>
            {wasQuarantined
              ? `Agents still do not see ${row.id}. The decision is saved in the audit log.`
              : `${row.id} is hidden from every agent until an admin approves it again.`}
          </StatusBox>
        </div>
      )}

      {isMcp && action && (
        <form onSubmit={(e) => void submit(e)} noValidate className="flex flex-col gap-2 px-3.5 pt-3">
          <Label htmlFor="tool-reason">Reason (required)</Label>
          <Textarea
            id="tool-reason"
            aria-invalid={!!error}
            aria-describedby={error ? "tool-reason-error" : undefined}
            placeholder={action === "approve" ? "e.g. vendor confirmed the change, description reviewed" : "e.g. description changed without a release note"}
            {...form.register("reason")}
          />
          {error && (
            <span id="tool-reason-error" className="text-[12px] text-dec-block">
              {error}
            </span>
          )}
          {(approve.isError || quarantine.isError) && (
            <StatusBox variant="error" title={action === "approve" ? "Could not approve" : "Could not quarantine"}>
              {(approve.error ?? quarantine.error)?.message}
            </StatusBox>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" disabled={pending}>
              {action === "approve"
                ? `Approve version ${shortHash(t?.current_hash)}`
                : quarantined
                  ? "Keep quarantined"
                  : "Quarantine tool"}
            </Button>
            <Button variant="ghost" onClick={() => setAction(null)}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      <SidebarActions>
        {isMcp && quarantined && (
          <>
            <Button
              variant="primary"
              disabled={!isAnalyst || pending}
              title={isAnalyst ? undefined : analystOnly}
              onClick={() => start("quarantine")}
            >
              {quarantineLabel}
            </Button>
            <Button disabled={!isAdmin || pending} title={isAdmin ? undefined : adminOnly} onClick={() => start("approve")}>
              {approveLabel}
            </Button>
            <Button
              variant="ghost"
              className="border-border text-dec-block"
              disabled
              title="Not available in the admin API yet: remove the server from tools.yaml"
            >
              Remove server
            </Button>
          </>
        )}
        {isMcp && row.status === "not approved" && (
          <>
            <Button variant="primary" disabled={!isAdmin || pending} title={isAdmin ? undefined : adminOnly} onClick={() => start("approve")}>
              {approveLabel}
            </Button>
            <Button disabled={!isAnalyst || pending} title={isAnalyst ? undefined : analystOnly} onClick={() => start("quarantine")}>
              {quarantineLabel}
            </Button>
          </>
        )}
        {isMcp && row.status === "approved" && (
          <>
            <Button disabled={!isAnalyst || pending} title={isAnalyst ? undefined : analystOnly} onClick={() => start("quarantine")}>
              {quarantineLabel}
            </Button>
            <Button asChild variant="ghost" className="border-border">
              <Link href="/policies?tab=yaml">Edit access</Link>
            </Button>
          </>
        )}
        {row.kind === "builtin" && (
          <Button asChild>
            <Link href="/policies?tab=yaml">Edit rules in Policies</Link>
          </Button>
        )}
      </SidebarActions>
    </>
  );
}
