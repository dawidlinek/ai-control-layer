"use client";

import * as React from "react";
import Link from "next/link";
import { SeverityChip, SidebarBlock, SidebarHeader, SidebarSection, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ICON_PATHS, PathIcon } from "@/components/rogatka";
import { useHasRole, useUser } from "@/lib/auth/user-context";
import { formatClock, formatDay, formatTime, formatWhen } from "@/lib/format";
import type { Incident } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { usePatchIncident } from "./api";
import { IncidentActions } from "./actions";
import { BreakerSection, FactsSection, RugPullSection } from "./evidence";
import {
  STATUS_LABEL,
  breakerOf,
  factsOf,
  rugPullOf,
  summaryOf,
  timelineOf,
  tracesOf,
  typeLabel,
  type IncidentStatus,
  type TimelineTone,
} from "./readers";

const STATUSES: IncidentStatus[] = ["open", "triaged", "resolved", "false_positive"];

/** Status pill classes: Open accent, Triaged muted, Resolved green. */
export function statusClass(s: IncidentStatus): string {
  return s === "open"
    ? "border-accent-line bg-accent-soft text-text"
    : s === "resolved"
      ? "border-dec-allow/45 bg-transparent text-dec-allow"
      : "border-border-strong bg-transparent text-muted";
}

const DOT: Record<TimelineTone, string> = { bad: "bg-dec-block", person: "bg-accent", system: "bg-muted" };

function StatusControl({ incident, onChanged }: { incident: Incident; onChanged: (id: string) => void }) {
  const canTriage = useHasRole("analyst");
  const patch = usePatchIncident();
  const label = STATUS_LABEL[incident.status];
  if (!canTriage) {
    return <span className={cn("rounded-[10px] border px-2.5 py-0.5 text-[12.5px]", statusClass(incident.status))}>{label}</span>;
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Status: ${label}`}
          disabled={patch.isPending}
          className={cn("inline-flex min-h-[30px] items-center gap-1.5 rounded-[6px] border px-2.5 text-[12.5px]", statusClass(incident.status))}
        >
          {label}
          <PathIcon path={ICON_PATHS.chevronDown} size={11} strokeWidth={2.4} />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent aria-label="Change status">
        <DropdownMenuRadioGroup
          value={incident.status}
          onValueChange={(v) => {
            if (v === incident.status) return;
            patch.mutate({ id: incident.id, status: v as IncidentStatus }, { onSuccess: () => onChanged(incident.id) });
          }}
        >
          {STATUSES.map((s) => (
            <DropdownMenuRadioItem key={s} value={s}>
              {STATUS_LABEL[s]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function AssignToMe({ incident, onChanged }: { incident: Incident; onChanged: (id: string) => void }) {
  const me = useUser();
  const canTriage = useHasRole("analyst");
  const patch = usePatchIncident();
  if (incident.assignee) {
    return (
      <span className="text-[12.5px] text-muted">
        Assignee{" "}
        <span className="text-text">
          {incident.assignee}
          {incident.assignee === me.username && " (you)"}
        </span>
      </span>
    );
  }
  if (!canTriage) return <span className="text-[12.5px] text-muted">Unassigned</span>;
  return (
    <>
      <Button
        size="sm"
        className="min-h-[30px]"
        disabled={patch.isPending}
        onClick={() => patch.mutate({ id: incident.id, assignee: me.username }, { onSuccess: () => onChanged(incident.id) })}
      >
        Assign to me
      </Button>
      {patch.isError && <span role="alert" className="text-[12px] text-dec-block">Could not assign: {patch.error.message}</span>}
    </>
  );
}

function NotesAndTimeline({ incident }: { incident: Incident }) {
  const canNote = useHasRole("analyst");
  const patch = usePatchIncident();
  const [text, setText] = React.useState("");
  const entries = timelineOf(incident);
  const today = (iso: string) => formatDay(iso) === "today";

  return (
    <SidebarSection title="Notes and timeline" className="border-b-0">
      {canNote && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const note = text.trim();
            if (!note) return;
            patch.mutate({ id: incident.id, note }, { onSuccess: () => setText("") });
          }}
        >
          <Input
            aria-label="Add a note"
            placeholder="Add a note for the team…"
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="min-h-[34px]"
          />
          <Button type="submit" className="min-h-[34px]" disabled={patch.isPending || !text.trim()}>
            Add
          </Button>
        </form>
      )}
      {patch.isError && (
        <StatusBox variant="error" title="Could not add the note">
          {patch.error.message}
        </StatusBox>
      )}
      {entries.length === 0 ? (
        <span className="text-[12.5px] text-muted">Nothing recorded yet.</span>
      ) : (
        <ol aria-label="Timeline" className="m-0 flex list-none flex-col p-0">
          {entries.map((e, idx) => (
            <li
              key={`${e.at}-${idx}`}
              data-tone={e.tone}
              className="grid grid-cols-[max-content_8px_minmax(0,1fr)] items-baseline gap-2 py-1 text-[12.5px]"
            >
              <time dateTime={e.at} title={formatWhen(e.at)} className="min-w-12 font-mono text-[11.5px] text-muted">
                {today(e.at) ? formatClock(e.at) : formatWhen(e.at)}
              </time>
              <span aria-hidden className={cn("size-[7px] rounded-full", DOT[e.tone])} />
              <span>
                <span className="text-muted">{e.who}</span> {e.text}
              </span>
            </li>
          ))}
        </ol>
      )}
      <Button
        variant="ghost"
        className="self-start border-border"
        disabled
        title="Not available in the admin API yet"
      >
        Export evidence
      </Button>
    </SidebarSection>
  );
}

export function IncidentSidebar({ incident, onChanged }: { incident: Incident; onChanged: (id: string) => void }) {
  const rug = rugPullOf(incident);
  const breaker = breakerOf(incident);
  const facts = factsOf(incident);
  const traces = tracesOf(incident);

  return (
    <>
      <SidebarHeader label="Incident" title={incident.id} copyText={incident.id} />
      <SidebarBlock>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityChip severity={incident.severity} size="md" />
          <span className="text-[12.5px] text-muted">{typeLabel(incident)}</span>
        </div>
        <h2 className="m-0 text-[16px] font-semibold leading-[1.35]">{incident.title}</h2>
        <p className="m-0 text-[13.5px] leading-[1.5]">{summaryOf(incident)}</p>
        <div className="flex flex-wrap items-center gap-2">
          <StatusControl incident={incident} onChanged={onChanged} />
          <AssignToMe incident={incident} onChanged={onChanged} />
          <div className="flex-1" />
          <span className="text-[12px] text-muted">opened {formatWhen(incident.created_at)}</span>
        </div>
      </SidebarBlock>

      {rug && <RugPullSection ev={rug} />}
      {breaker && <BreakerSection ev={breaker} ruleId={incident.rule_ids[0]} />}
      {facts && <FactsSection ev={facts} />}

      <IncidentActions key={incident.id} incident={incident} onChanged={onChanged} />

      <SidebarSection title="Linked traces">
        {traces.length === 0 ? (
          <span className="text-[12.5px] text-muted">No linked traces.</span>
        ) : (
          <ul aria-label="Linked traces" className="m-0 flex list-none flex-col gap-1.5 p-0">
            {traces.map((t) => {
              const body = (
                <>
                  <span className="font-mono text-[12px] text-muted">{t.at ? formatTime(t.at) : ""}</span>
                  <span className="font-mono text-[12px]">{t.id}</span>
                  <span className="min-w-0 truncate text-muted">{t.what}</span>
                  <span aria-hidden className="text-muted">
                    ›
                  </span>
                </>
              );
              const cls =
                "grid grid-cols-[66px_90px_minmax(0,1fr)_14px] items-center gap-2 rounded-[6px] border border-border px-2 py-1.5 text-[12.5px] text-text no-underline";
              return (
                <li key={t.id}>
                  {t.id.startsWith("tr_") || t.id.startsWith("evt_") ? (
                    <Link href={`/traffic?sel=${encodeURIComponent(t.id)}`} className={cn(cls, "hover:border-border-strong")}>
                      {body}
                    </Link>
                  ) : (
                    <div className={cls}>{body}</div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </SidebarSection>

      <NotesAndTimeline incident={incident} />
    </>
  );
}
