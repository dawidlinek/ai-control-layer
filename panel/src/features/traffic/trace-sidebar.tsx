"use client";

import * as React from "react";
import Link from "next/link";
import {
  DecisionBadge,
  DecisionChips,
  ErrorState,
  FactsGrid,
  ICON_PATHS,
  LoadingRows,
  PathIcon,
  PlainSentence,
  RuleChip,
  SidebarActions,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  StepTimeline,
  type TimelineStep,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { RequireRole } from "@/lib/auth/user-context";
import type { EventSummary, EventTrace, TraceControl, TraceStep } from "@/lib/api/types";
import { formatClock, formatDay, formatTime } from "@/lib/format";
import { useTrace } from "./api";
import {
  clientLine,
  decisionsOf,
  isSensitiveLabel,
  modelOrTool,
  pointLabel,
  riskLabel,
  RULE_ID_RE,
  whoName,
  type NameOf,
} from "./model";
import { RedactedText, SessionLabelLine } from "./parts";

const STEP_NAME: Record<TraceStep["step"], string> = {
  identity: "Identity",
  normalise: "Normalise",
  rules: "Rules",
  similarity: "Similarity",
  classifier: "Classifier",
  judge: "Judge",
  decide: "Decide",
  approval: "Approval",
  route: "Route",
  output: "Output",
};

export const NO_ENDPOINT = "Not available in the admin API yet";

/** The trace sidebar of Traffic: header, decision + sentence + facts, what the model saw, how the decision was made. */
export function TraceSidebar({ id, row, nameOf }: { id: string; row?: EventSummary; nameOf: NameOf }) {
  const trace = useTrace(row?.event_id ?? id);
  const event = trace.data?.event ?? row;
  const traceId = event?.trace_id ?? event?.event_id ?? id;

  return (
    <>
      <SidebarHeader label="Trace" title={traceId} copyText={traceId} />
      {trace.isPending && !event && <LoadingRows rows={5} />}
      {trace.isError && !event && (
        <ErrorState title="Could not load this trace" error={trace.error} onRetry={() => void trace.refetch()} />
      )}
      {event && (
        <>
          <Summary event={event} nameOf={nameOf} />
          {trace.data?.model_saw && <ModelSaw text={trace.data.model_saw} note={trace.data.model_saw_note} />}
          <SidebarSection
            title="How the decision was made"
            aside={event.latency_ms != null ? `${formatMs(event.latency_ms)} added by Rogatka` : undefined}
          >
            {trace.data ? (
              <Timeline trace={trace.data} />
            ) : trace.isError ? (
              <ErrorState title="Could not load the steps" error={trace.error} onRetry={() => void trace.refetch()} />
            ) : (
              <LoadingRows rows={4} />
            )}
          </SidebarSection>
          <SidebarActions>
            <span title={NO_ENDPOINT} className="inline-flex">
              <Button disabled title={NO_ENDPOINT}>
                Replay with live policy
              </Button>
            </span>
            <RequireRole min="analyst">
              <span title={NO_ENDPOINT} className="inline-flex">
                <Button disabled title={NO_ENDPOINT}>
                  Add to incident
                </Button>
              </span>
            </RequireRole>
          </SidebarActions>
        </>
      )}
    </>
  );
}

function formatMs(ms: number): string {
  return `${ms < 10 ? Math.round(ms * 10) / 10 : Math.round(ms)} ms`;
}

function fallbackSentence(e: EventSummary, nameOf: NameOf): string {
  const d = decisionsOf(e);
  return `${whoName(e, nameOf)}’s ${pointLabel(e.point)} was checked by Rogatka${d.length ? `: ${d.join(", ")}` : ""}.`;
}

function Summary({ event, nameOf }: { event: EventSummary; nameOf: NameOf }) {
  const facts = [
    { label: "Who", value: `${whoName(event, nameOf)} · ${clientLine(event)}` },
    { label: "When", value: `${formatDay(event.timestamp)} ${formatTime(event.timestamp)}`, mono: true },
    { label: "Point", value: pointLabel(event.point) },
    { label: "Model / tool", value: modelOrTool(event), mono: true },
    { label: "Data class", value: event.data_class ?? "—" },
    { label: "Risk score", value: riskLabel(event.risk_score), mono: true },
  ];
  return (
    <SidebarBlock>
      <DecisionChips decisions={decisionsOf(event)} size="md" />
      <PlainSentence>{event.summary || fallbackSentence(event, nameOf)}</PlainSentence>
      <FactsGrid facts={facts} />
      {isSensitiveLabel(event.session_label) && <SessionLabelLine label={event.session_label} />}
      <SessionLink event={event} />
    </SidebarBlock>
  );
}

/** "Open full conversation →" (LibreChat) or "Open full session →" (OpenCode / agent). */
function SessionLink({ event }: { event: EventSummary }) {
  const ref = event.client_ref;
  const id = ref?.id ?? event.session_id;
  if (!id) return null;
  const conversation = ref?.kind === "conversation";
  const unit = event.agent_id ? "steps" : "messages";
  const sub = ref
    ? [ref.id, ref.client, `${ref.message_count} ${ref.message_count === 1 ? unit.slice(0, -1) : unit}`, `started ${formatClock(ref.started_at)}`].join(" · ")
    : id;
  return (
    <Link
      href={`/sessions/${encodeURIComponent(id)}`}
      className="flex items-center gap-2.5 rounded-[6px] border border-accent-line bg-accent-soft px-3 py-2.5 text-text no-underline hover:text-text"
    >
      <PathIcon path={ICON_PATHS.conversation} size={16} className="shrink-0 text-text" />
      <span className="flex min-w-0 flex-1 flex-col">
        <b className="font-semibold">{conversation ? "Open full conversation" : "Open full session"}</b>
        <span className="truncate text-[12px] text-muted">{sub}</span>
      </span>
      <span aria-hidden className="text-text">
        →
      </span>
    </Link>
  );
}

function ModelSaw({ text, note }: { text: string; note: string }) {
  return (
    <SidebarSection title="What the model saw">
      <div className="rounded-[6px] border border-border bg-inset px-3 py-2.5 text-[13px] leading-[1.9]" data-testid="model-saw">
        <RedactedText text={text} />
      </div>
      {note && <span className="text-[12px] text-muted">{note}</span>}
    </SidebarSection>
  );
}

function scoreText(c: TraceControl): string | null {
  if (c.score == null) return null;
  if (c.threshold == null) return c.score.toFixed(2);
  return `${c.score.toFixed(2)} ${c.score >= c.threshold ? "≥" : "<"} ${c.threshold.toFixed(2)}`;
}

function ControlRow({ c }: { c: TraceControl }) {
  const rule = c.rule_ids[0] ?? c.control_id;
  const score = scoreText(c);
  return (
    <div
      data-control={c.control_id}
      className="grid grid-cols-[minmax(0,1fr)_max-content] gap-x-2.5 gap-y-0.5 border-b border-border px-2.5 py-[7px] text-[12px] last:border-b-0"
    >
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">
        <RuleChip ruleId={rule} href={RULE_ID_RE.test(rule) ? undefined : false} />
        <span>{c.reason ?? c.control_type}</span>
        {c.findings.length > 0 && <span className="font-mono text-[11px] text-muted">{c.findings.join(" · ")}</span>}
      </span>
      {c.action === "allow" ? (
        <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-[4px] border border-border py-0 pl-1 pr-1.5 font-mono text-[11px] text-muted">
          <PathIcon path={ICON_PATHS.check} size={11} strokeWidth={2.4} />
          pass
        </span>
      ) : (
        <DecisionBadge decision={c.action} />
      )}
      {score && <span className="font-mono text-[11px] text-muted">{score}</span>}
    </div>
  );
}

function Timeline({ trace }: { trace: EventTrace }) {
  const steps: TimelineStep[] = trace.steps.map((s) => ({
    id: s.step,
    name: STEP_NAME[s.step],
    result: s.result || "—",
    meta: s.ms != null ? formatMs(s.ms) : undefined,
    changed: s.changed,
    detail: s.controls.length ? s.controls.map((c, i) => <ControlRow key={`${c.control_id}-${i}`} c={c} />) : undefined,
  }));
  const firstOpen = trace.steps.find((s) => s.changed && s.controls.length)?.step ?? null;
  return <StepTimeline key={trace.event.event_id} steps={steps} defaultOpenId={firstOpen} ariaLabel="How the decision was made" />;
}
