"use client";

import Link from "next/link";
import { DecisionChips, EmptyState, ErrorState, LoadingRows, PageHeader, RuleChip } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api/client";
import type { SessionTranscript, TranscriptTurn } from "@/lib/api/types";
import { formatClock, formatDay, formatTime } from "@/lib/format";
import { usePeople } from "@/features/traffic/api";
import { decisionsOf, isAllowedOnly, isSensitiveLabel, type NameOf } from "@/features/traffic/model";
import { RedactedText, SessionLabelLine } from "@/features/traffic/parts";
import { useTranscript } from "./api";

const ROLE_LABEL: Record<TranscriptTurn["role"], string> = {
  user: "User",
  assistant: "Assistant",
  tool_call: "Tool call",
  tool_result: "Tool result",
  system: "System",
};

function titleOf(id: string, t?: SessionTranscript): string {
  return t?.client_ref?.kind === "conversation" ? `Conversation ${id}` : `Session ${id}`;
}

function subtitleOf(t: SessionTranscript, nameOf: NameOf): string {
  const who = t.username ? nameOf(t.username) : (t.subject ?? "unknown");
  const ref = t.client_ref;
  const agent = t.subject?.startsWith("agent-");
  const count = ref?.message_count ?? t.turns.length;
  return [
    who,
    ref?.client,
    t.groups[0],
    `${count} ${agent ? "steps" : count === 1 ? "message" : "messages"}`,
    t.started_at ? `started ${formatDay(t.started_at)} ${formatClock(t.started_at)}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

/**
 * Session / conversation view (`/sessions/[id]`): the read-only, redacted transcript Rogatka recorded, one card per
 * turn with its decision and rules, linking back to the trace in Traffic. Not designed in the prototypes; it follows
 * the shell and the trace sidebar look.
 */
export function SessionScreen({ id }: { id: string }) {
  const transcript = useTranscript(id);
  const people = usePeople();
  const t = transcript.data;
  const notFound = transcript.error instanceof ApiError && transcript.error.status === 404;

  return (
    <>
      <PageHeader
        title={titleOf(id, t)}
        subtitle={t ? subtitleOf(t, people.nameOf) : undefined}
        actions={
          <Button asChild variant="secondary">
            <Link href={`/traffic?q=${encodeURIComponent(id)}`}>All requests in Traffic →</Link>
          </Button>
        }
      />
      {transcript.isPending && (
        <div className="rounded-[8px] border border-border bg-surface">
          <LoadingRows rows={4} />
        </div>
      )}
      {notFound && (
        <div className="rounded-[8px] border border-border bg-surface">
          <EmptyState
            title="This session is not in the audit log"
            action={
              <Button asChild variant="secondary" className="mt-2">
                <Link href="/traffic">Back to Traffic</Link>
              </Button>
            }
          >
            Rogatka has no requests recorded for {id}. The link may be wrong, or the session is older than the retention period.
          </EmptyState>
        </div>
      )}
      {transcript.isError && !notFound && (
        <div className="rounded-[8px] border border-border bg-surface">
          <ErrorState title="Could not load this session" error={transcript.error} onRetry={() => void transcript.refetch()} />
        </div>
      )}
      {t && (
        <>
          {isSensitiveLabel(t.session_label) && <SessionLabelLine label={t.session_label} className="self-start" />}
          <p className="m-0 text-[12.5px] text-muted">
            Read-only. Shown as Rogatka recorded it: personal data and secrets appear as placeholders.
          </p>
          {t.truncated && <p className="m-0 text-[12.5px] text-muted">Only the most recent turns are shown.</p>}
          {t.turns.length === 0 ? (
            <div className="rounded-[8px] border border-border bg-surface">
              <EmptyState title="No turns recorded" />
            </div>
          ) : (
            <ol aria-label="Turns" className="m-0 flex max-w-[880px] list-none flex-col p-0">
              {t.turns.map((turn, i) => (
                <Turn key={turn.event_id} turn={turn} last={i === t.turns.length - 1} who={t.username ? people.nameOf(t.username) : null} />
              ))}
            </ol>
          )}
        </>
      )}
    </>
  );
}

function Turn({ turn, who, last }: { turn: TranscriptTurn; who: string | null; last: boolean }) {
  const traceRef = turn.trace_id ?? turn.event_id;
  const role = turn.role === "user" && who ? who : ROLE_LABEL[turn.role];
  const what = turn.model ?? turn.tool;
  return (
    <li data-turn={turn.event_id} data-role={turn.role} className="grid grid-cols-[20px_minmax(0,1fr)] gap-x-3">
      {/* brand motif (STYLEGUIDE section 4): 2 px accent rail, 12 px hollow ring per turn, 14 px filled dot for the last */}
      <span aria-hidden className="flex flex-col items-center">
        <span className={last ? "mt-[15px] size-3.5 shrink-0 rounded-full border-2 border-accent bg-accent" : "mt-4 size-3 shrink-0 rounded-full border-2 border-accent bg-bg"} />
        <span className={last ? "w-0.5 flex-1 bg-transparent" : "w-0.5 flex-1 bg-accent"} />
      </span>
      <div className="mb-2.5 flex flex-col gap-2 rounded-[8px] border border-border bg-surface px-3.5 py-3">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5 text-[13.5px]">
          <b className="font-semibold">{role}</b>
          <time dateTime={turn.timestamp} className="font-mono text-[12px] text-muted">
            {formatTime(turn.timestamp)}
          </time>
          {what && <span className="font-mono text-[12px] text-muted">{what}</span>}
          <div className="flex-1" />
          <DecisionChips decisions={decisionsOf(turn)} />
          {turn.rule_ids.map((r) => (
            <RuleChip key={r} ruleId={r} />
          ))}
          <Link href={`/traffic?sel=${encodeURIComponent(traceRef)}`} className="font-mono text-[12px]" aria-label={`Open trace ${traceRef} in Traffic`}>
            {traceRef} →
          </Link>
        </div>
        {turn.text ? (
          <div className={turn.role === "tool_call" ? "font-mono text-[13px]" : "text-[14px] leading-[1.7]"}>
            <RedactedText text={turn.text} />
          </div>
        ) : (
          <span className="text-[13.5px] italic text-muted">Content not retained.</span>
        )}
        {!isAllowedOnly(turn) && turn.summary && <p className="m-0 text-[13.5px] text-muted">{turn.summary}</p>}
      </div>
    </li>
  );
}
