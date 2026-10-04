"use client";

import * as React from "react";
import { DiffBox, Meter, RuleChip, SidebarSection, useNow } from "@/components/rogatka";
import { DECISION_VAR } from "@/lib/decisions";
import { formatClock, formatCountdown, formatDay } from "@/lib/format";
import { cn } from "@/lib/utils";
import { shortHash, type BreakerEvidence, type BreakerStateName, type FactsEvidence, type RugPullEvidence } from "./readers";

const tint = (v: string) => ({ "--c": v }) as React.CSSProperties;

export function RugPullSection({ ev }: { ev: RugPullEvidence }) {
  return (
    <SidebarSection title="What changed in the tool">
      <dl className="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        <dt className="text-muted">Server · tool</dt>
        <dd className="m-0 font-mono">
          {ev.server} › {ev.tool}
        </dd>
        {ev.approvedHash && (
          <>
            <dt className="text-muted">Approved version</dt>
            <dd className="m-0 font-mono">
              {shortHash(ev.approvedHash)}
              {ev.approvedAt && ` · ${formatDay(ev.approvedAt)}`}
            </dd>
          </>
        )}
        {ev.newHash && (
          <>
            <dt className="text-muted">Now</dt>
            <dd className="m-0 font-mono text-dec-block">
              {shortHash(ev.newHash)}
              {ev.changedAt && ` · ${formatClock(ev.changedAt)} ${formatDay(ev.changedAt)}`}
            </dd>
          </>
        )}
      </dl>
      {ev.diff.length > 0 && <DiffBox title="Tool description" lines={ev.diff} addedTone="bad" ariaLabel="Tool description diff" />}
      {ev.findings.length > 0 && (
        <ul aria-label="Findings" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {ev.findings.map((f) => (
            <li key={f} className="tint rounded-[10px] px-2 py-px text-[11.5px]" style={tint(DECISION_VAR.block)}>
              {f}
            </li>
          ))}
        </ul>
      )}
      {ev.callsSinceChange !== null && (
        <span className="text-[12px] text-muted">
          {ev.sessionsListed !== null && `${ev.sessionsListed} sessions had this tool listed · `}
          {ev.callsSinceChange === 0
            ? "0 calls since the change — it was quarantined before anyone used it."
            : `${ev.callsSinceChange} calls since the change.`}
        </span>
      )}
    </SidebarSection>
  );
}

const STATES: { key: BreakerStateName; label: string }[] = [
  { key: "closed", label: "closed" },
  { key: "open", label: "OPEN" },
  { key: "half_open", label: "half-open" },
];

const STATE_VAR: Record<BreakerStateName, string> = {
  closed: DECISION_VAR.allow,
  open: DECISION_VAR.block,
  half_open: DECISION_VAR.require_approval,
};

function HalfOpenIn({ at }: { at: string }) {
  const now = useNow(1000);
  return Date.parse(at) > now ? <>half-open in {formatCountdown(at, now)}</> : <>half-open now</>;
}

export function BreakerSection({ ev, ruleId }: { ev: BreakerEvidence; ruleId?: string }) {
  return (
    <SidebarSection title="Circuit breaker">
      {ev.state && (
      <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
        <ol aria-label="Breaker states" className="m-0 flex list-none items-center gap-1.5 p-0">
          {STATES.map((s, i) => {
            const on = s.key === ev.state;
            return (
              <li key={s.key} className="flex items-center gap-1.5">
                <span
                  aria-current={on ? "step" : undefined}
                  className={cn("rounded-[12px] border px-2.5 py-[3px]", on ? "tint font-semibold" : "border-border text-muted")}
                  style={on ? tint(STATE_VAR[s.key]) : undefined}
                >
                  {on ? s.label : s.label.toLowerCase()}
                </span>
                {i < STATES.length - 1 && (
                  <span aria-hidden className="text-muted">
                    →
                  </span>
                )}
              </li>
            );
          })}
        </ol>
        {ev.state === "open" && ev.halfOpenAt && (
          <span className="ml-auto font-mono text-muted" data-testid="half-open">
            <HalfOpenIn at={ev.halfOpenAt} />
          </span>
        )}
      </div>
      )}
      {ev.used !== null && ev.limit !== null && (
        <div className="flex flex-col gap-1">
          <div className="flex justify-between text-[12px]">
            <span className="text-muted">
              {ev.meter}
              {ev.sessionId && `, session ${ev.sessionId}`}
            </span>
            <span className="font-mono">
              {ev.used} / {ev.limit}
            </span>
          </div>
          <Meter
            value={ev.used}
            max={ev.limit}
            danger={ev.state === "open"}
            label={`${ev.meter}${ev.sessionId ? `, session ${ev.sessionId}` : ""}`}
            className="h-2"
          />
        </div>
      )}
      {(ev.cause || ruleId) && (
        <div className="text-[12.5px]">
          Cause: {ruleId && <RuleChip ruleId={ruleId} />} {ev.cause}
        </div>
      )}
    </SidebarSection>
  );
}

/** Evidence of the kinds without a dedicated section: labelled rows and tags, no raw values. */
export function FactsSection({ ev }: { ev: FactsEvidence }) {
  if (ev.rows.length === 0 && ev.tags.length === 0) return null;
  return (
    <SidebarSection title={ev.title}>
      {ev.rows.length > 0 && (
        <dl className="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
          {ev.rows.map((r) => (
            <React.Fragment key={r.label}>
              <dt className="text-muted">{r.label}</dt>
              <dd className={cn("m-0 min-w-0 break-words", r.mono && "font-mono")}>{r.value}</dd>
            </React.Fragment>
          ))}
        </dl>
      )}
      {ev.tags.length > 0 && (
        <ul aria-label={ev.tagsLabel ?? "Tags"} className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {ev.tags.map((t) => (
            <li key={t} className="tint rounded-[10px] px-2 py-px text-[11.5px]" style={tint(DECISION_VAR.block)}>
              {t}
            </li>
          ))}
        </ul>
      )}
    </SidebarSection>
  );
}
