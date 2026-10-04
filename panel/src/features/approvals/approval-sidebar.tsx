"use client";

import * as React from "react";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  DecisionBadge,
  DiffBox,
  FactsGrid,
  PlainSentence,
  RuleChip,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StatusBox,
  useNow,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useHasRole } from "@/lib/auth/user-context";
import { DECISION_VAR } from "@/lib/decisions";
import { formatClock, formatCountdown, formatTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useDecideApproval } from "./api";
import type { ApprovalRow } from "./model";
import { approvalSentence, promptOf, riskLabel, ruleSentence, sourceDecision, targetOf, clientApp } from "./readers";

const ELEVATIONS = [5, 15, 60] as const;
type Elevation = (typeof ELEVATIONS)[number];

type Result = { kind: "deny" } | { kind: "once" } | { kind: "elev"; minutes: number; until: string };

const tintStyle = (v: string) => ({ "--c": v }) as React.CSSProperties;

function AutoDenyPill({ until }: { until: string }) {
  const now = useNow(1000);
  return (
    <span
      className="rounded-[10px] border px-2 py-px text-[12px]"
      style={{ color: DECISION_VAR.require_approval, borderColor: `color-mix(in srgb, ${DECISION_VAR.require_approval} 32%, transparent)` }}
    >
      auto-deny in <b className="font-mono font-semibold">{formatCountdown(until, now)}</b>
    </span>
  );
}

export function ApprovalSidebar({ row, onDecided }: { row: ApprovalRow; onDecided: (id: string) => void }) {
  const { a, parsed, reason, who } = row;
  const pending = a.status === "pending";
  const sessionLabel = who.isAgent
    ? `${a.requested_by} run ${a.session_id}`
    : [`${clientApp(a) ?? a.server ?? ""} ${a.session_id}`.trim(), parsed.device].filter(Boolean).join(" · ");
  const rule = a.rule_ids[0];
  const hasWhy = !!rule || reason.sources.length > 0;

  return (
    <>
      <SidebarHeader
        label="Approval"
        title={a.id}
        copyText={a.id}
        actions={
          <>
            <span className="text-[12.5px] text-muted">held {formatTime(a.created_at)}</span>
            {pending && <AutoDenyPill until={a.expires_at} />}
          </>
        }
      />
      <SidebarBlock>
        <div>
          <DecisionBadge decision="require_approval" size="md" />
        </div>
        <PlainSentence>{approvalSentence(a, parsed, reason, who)}</PlainSentence>
        <FactsGrid
          facts={[
            { label: "Session", value: sessionLabel },
            { label: "Risk score", value: riskLabel(a.risk_score), mono: true },
            { label: "Data class", value: parsed.dataClass ?? "not recorded" },
            {
              label: "Trace",
              mono: true,
              value: (
                <Link href={`/traffic?sel=${encodeURIComponent(a.trace_id)}`} className="text-accent">
                  {a.trace_id}
                </Link>
              ),
            },
          ]}
        />
      </SidebarBlock>

      <SidebarSection title="What it wants to do">
        <div className="rg-scroll overflow-x-auto whitespace-nowrap rounded-[6px] border border-border bg-inset px-3 py-2.5 font-mono text-[13px]">
          <span className="text-muted">{promptOf(a)}</span> <span data-testid="approval-command">{parsed.command || "—"}</span>
        </div>
        {parsed.details.length > 0 && (
          <dl className="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-[5px] text-[12.5px]">
            {parsed.details.map((d) => (
              <React.Fragment key={d.key}>
                <dt className="text-muted">{d.key}</dt>
                <dd className="m-0 flex min-w-0 flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[12px]">{d.value}</span>
                  {d.flag && (
                    <span className="tint rounded-[10px] px-[7px] text-[11.5px]" style={tintStyle(DECISION_VAR.require_approval)}>
                      {d.flag}
                    </span>
                  )}
                </dd>
              </React.Fragment>
            ))}
          </dl>
        )}
        {parsed.preview && <DiffBox title={parsed.preview.title} lines={parsed.preview.lines} ariaLabel="Preview" />}
      </SidebarSection>

      {hasWhy && (
        <SidebarSection title="Why it was held">
          <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
            {rule && <RuleChip ruleId={rule} />}
            <span>{ruleSentence(rule, reason)}</span>
          </div>
          {reason.sources.length > 0 && (
            <ol className="m-0 flex list-none flex-col gap-1.5 p-0" aria-label="Reasons">
              {reason.sources.map((s) => {
                const v = DECISION_VAR[sourceDecision(s.flag)];
                const href = s.traceId ? `/traffic?sel=${encodeURIComponent(s.traceId)}` : `/traffic?q=${encodeURIComponent(a.session_id)}`;
                return (
                  <li
                    key={s.n}
                    className="tint grid grid-cols-[22px_92px_minmax(0,1fr)_max-content] items-center gap-2 rounded-[6px] px-2.5 py-[7px] text-[12.5px]"
                    style={tintStyle(v)}
                  >
                    <span
                      aria-hidden
                      className="inline-flex size-5 items-center justify-center rounded-full border-[1.5px] text-[11px] font-semibold"
                      style={{ borderColor: v }}
                    >
                      {s.n}
                    </span>
                    <span className="font-mono text-[12px]">{s.flag}</span>
                    <span className="min-w-0 text-text">{s.text}</span>
                    <Link href={href} className="font-mono text-[11.5px] text-accent">
                      {s.at ? formatTime(s.at) : "now"}
                    </Link>
                  </li>
                );
              })}
            </ol>
          )}
          <Link href={`/sessions/${encodeURIComponent(a.session_id)}`} className="self-start text-[12.5px] text-accent">
            Open full session {a.session_id} →
          </Link>
        </SidebarSection>
      )}

      <DecisionPanel row={row} onDecided={onDecided} />
    </>
  );
}

const reasonSchema = z.object({ reason: z.string().trim().min(1, "Write a reason to approve.") });
type ReasonForm = z.infer<typeof reasonSchema>;

function decidedText(row: ApprovalRow): string {
  const { a } = row;
  if (a.status === "approved") {
    return a.elevation
      ? `Approved by ${a.decided_by ?? "an approver"} · elevation until ${formatClock(a.elevation.until)}.`
      : `Approved once by ${a.decided_by ?? "an approver"}.`;
  }
  if (a.status === "denied") return `Denied by ${a.decided_by ?? "an approver"}.`;
  return "Nobody answered in 10 minutes, so it was denied automatically.";
}

function DecisionPanel({ row, onDecided }: { row: ApprovalRow; onDecided: (id: string) => void }) {
  const { a, parsed } = row;
  const canDecide = useHasRole("analyst");
  const decide = useDecideApproval();
  const [minutes, setMinutes] = React.useState<Elevation>(15);
  const [result, setResult] = React.useState<Result | null>(null);
  const [lastAction, setLastAction] = React.useState<"approve" | "deny">("approve");
  const form = useForm<ReasonForm>({ resolver: zodResolver(reasonSchema), defaultValues: { reason: "" } });
  const reasonId = React.useId();
  const errorId = React.useId();
  const target = targetOf(a, parsed);
  const rule = a.rule_ids[0];

  async function run(kind: Result["kind"], note: string) {
    setLastAction(kind === "deny" ? "deny" : "approve");
    const elevationMinutes = kind === "elev" ? minutes : undefined;
    const updated = await decide.mutateAsync({ id: a.id, decision: kind === "deny" ? "deny" : "approve", elevationMinutes, note });
    onDecided(a.id);
    setResult(
      kind === "elev"
        ? { kind, minutes, until: updated.elevation?.until ?? new Date(Date.now() + minutes * 60_000).toISOString() }
        : { kind },
    );
  }

  const approve = (kind: "once" | "elev") =>
    form.handleSubmit(async (v) => {
      try {
        await run(kind, v.reason);
      } catch {
        /* shown via decide.isError */
      }
    });

  const deny = async () => {
    form.clearErrors();
    try {
      await run("deny", form.getValues("reason"));
    } catch {
      /* shown via decide.isError */
    }
  };

  const reasonError = form.formState.errors.reason?.message;

  return (
    <section aria-label="Decision" className="flex flex-col gap-2.5 bg-raised p-3.5">
      {result?.kind === "deny" && (
        <StatusBox variant="error" title="Denied">
          The client shows the denial with rule {rule ?? "—"} and trace {a.trace_id}.
        </StatusBox>
      )}
      {result?.kind === "once" && (
        <StatusBox variant="success" title="Approved once">
          {target} runs now. Anything similar later is held again.
        </StatusBox>
      )}
      {result?.kind === "elev" && (
        <StatusBox variant="success" title={`Approved for ${result.minutes} minutes`}>
          {target} is allowed until {formatClock(result.until)}. It shows as an elevation on {row.who.name}’s access page.
        </StatusBox>
      )}
      {!result && a.status !== "pending" && <StatusBox variant="info">Decided: {decidedText(row)}</StatusBox>}

      {!result && a.status === "pending" && !canDecide && (
        <p className="m-0 text-[12.5px] text-muted">You can see this request. Approving or denying it needs the analyst or admin role.</p>
      )}

      {!result && a.status === "pending" && canDecide && (
        <form
          className="flex flex-col gap-2.5"
          onSubmit={(e) => {
            e.preventDefault();
            void approve("once")();
          }}
          noValidate
        >
          <div className="flex flex-col gap-1">
            <label htmlFor={reasonId} className="text-[12px] text-muted">
              Reason (required to approve)
            </label>
            <input
              id={reasonId}
              {...form.register("reason")}
              placeholder="e.g. pushes to a private remote"
              aria-invalid={!!reasonError}
              aria-describedby={reasonError ? errorId : undefined}
              className={cn(
                "min-h-[34px] rounded-[6px] border bg-surface px-2.5 text-[13px] text-text placeholder:text-muted",
                reasonError ? "border-dec-block" : "border-border",
              )}
            />
            {reasonError && (
              <span id={errorId} role="alert" className="text-[12px] text-dec-block">
                {reasonError}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="danger" size="lg" onClick={() => void deny()} disabled={decide.isPending}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" aria-hidden>
                <path d="M6 6l12 12 M18 6L6 18" />
              </svg>
              Deny
            </Button>
            <Button
              size="lg"
              className="border-border-strong bg-surface font-normal"
              onClick={() => void approve("once")()}
              disabled={decide.isPending}
            >
              Approve once
            </Button>
            <span className="inline-flex items-stretch overflow-hidden rounded-[6px] border border-border-strong">
              <button
                type="button"
                onClick={() => void approve("elev")()}
                disabled={decide.isPending}
                aria-label={`Approve for ${minutes} minutes`}
                className="min-h-9 border-0 border-r border-border-strong bg-surface px-3 text-[13px] text-text hover:bg-raised disabled:opacity-50"
              >
                Approve for
              </button>
              <span role="group" aria-label="Elevation length" className="inline-flex">
                {ELEVATIONS.map((m) => (
                  <button
                    key={m}
                    type="button"
                    aria-pressed={minutes === m}
                    onClick={() => setMinutes(m)}
                    className={cn(
                      "min-w-[42px] border-0 border-r border-border font-mono text-[12px] last:border-r-0",
                      minutes === m ? "bg-accent-soft text-text" : "bg-surface text-muted hover:text-text",
                    )}
                  >
                    {m}m
                  </button>
                ))}
              </span>
            </span>
          </div>
          <span className="text-[12px] text-muted">“Approve for” allows only this exact action, for the chosen time, then it is held again.</span>
          {decide.isError && (
            <StatusBox variant="error" title={lastAction === "deny" ? "Could not deny" : "Could not approve"}>
              {decide.error.message}
            </StatusBox>
          )}
        </form>
      )}
    </section>
  );
}
