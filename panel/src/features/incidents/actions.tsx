"use client";

import * as React from "react";
import Link from "next/link";
import { SidebarSection, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useHasRole } from "@/lib/auth/user-context";
import type { Role } from "@/lib/auth/roles";
import type { Incident } from "@/lib/api/types";
import { useApproveTool, usePatchIncident, useQuarantineTool, useResetBreaker } from "./api";
import { approvalIdOf, breakerOf, incidentKind, isClosed, previousPolicyVersion, rugPullOf, shortHash } from "./readers";

const NO_ENDPOINT = "Not available in the admin API yet";

type Run = () => Promise<{ title: string; text: string }>;

interface ActionDef {
  label: string;
  /** Mutating action: minimum role. Links need none. */
  min?: Role;
  run?: Run;
  href?: string;
  /** Opens an inline form instead of running directly. */
  form?: "reapprove";
  /** Rendered disabled with this title. */
  disabled?: string;
}

interface Built {
  actions: ActionDef[];
  note?: string;
}

function useActions(i: Incident): Built {
  const patch = usePatchIncident();
  const quarantine = useQuarantineTool();
  const resetBreaker = useResetBreaker();
  const close = (note: string, title = "Resolved") => async () => {
    await patch.mutateAsync({ id: i.id, status: "resolved", note });
    return { title, text: "The incident moves to the Resolved tab." };
  };

  if (isClosed(i.status)) {
    return {
      actions: [
        {
          label: "Reopen",
          min: "analyst",
          run: async () => {
            await patch.mutateAsync({ id: i.id, status: "open" });
            return { title: "Reopened", text: "The incident is open again and counts in the sidebar." };
          },
        },
      ],
    };
  }

  const kind = incidentKind(i);
  switch (kind) {
    case "mcp_rug_pull": {
      const ev = rugPullOf(i)!;
      return {
        actions: [
          {
            label: "Keep quarantined and close",
            min: "admin",
            run: async () => {
              await quarantine.mutateAsync({ toolId: ev.toolId, reason: `kept quarantined (${i.id})` });
              await patch.mutateAsync({ id: i.id, status: "resolved", note: `kept ${ev.tool || ev.toolId} quarantined and closed the incident` });
              return { title: "Kept quarantined", text: `${ev.tool || ev.toolId} stays hidden from every client. The incident is resolved.` };
            },
          },
          { label: "Re-approve new version…", min: "admin", form: "reapprove" },
          { label: "Remove server", disabled: NO_ENDPOINT },
        ],
        note: "Re-approving needs a policy admin and the first 4 characters of the new hash.",
      };
    }
    case "budget_breach": {
      const ev = breakerOf(i)!;
      return {
        actions: [
          ev.breakerId
            ? {
                label: "Reset breaker",
                min: "admin",
                run: async () => {
                  await resetBreaker.mutateAsync({ breakerId: ev.breakerId! });
                  await patch.mutateAsync({ id: i.id, status: "resolved", note: `reset the breaker for ${ev.sessionId ?? ev.breakerId}` });
                  return {
                    title: "Breaker reset",
                    text: `The breaker for ${ev.sessionId ?? ev.breakerId} is closed again, so calls can continue. The incident is resolved.`,
                  };
                },
              }
            : { label: "Reset breaker", disabled: "This incident does not name a breaker" },
          { label: "Raise limit…", href: "/budgets" },
          { label: "Keep blocked", min: "analyst", run: close("kept the breaker open", "Kept blocked") },
        ],
        note: "Raising the limit edits budgets.yaml and creates a new policy version.",
      };
    }
    case "rule_of_two": {
      const apr = approvalIdOf(i);
      return {
        actions: [
          apr ? { label: "Open approval", href: `/approvals?sel=${encodeURIComponent(apr)}` } : { label: "Open approval", href: "/approvals" },
          { label: `Revoke bash for ${i.subject?.split(" ")[0] ?? "this user"}…`, href: "/grants" },
          { label: "Close as expected", min: "analyst", run: close("closed as expected") },
        ],
      };
    }
    case "forbidden_model":
      return {
        actions: [
          { label: "Grant access…", href: "/grants" },
          { label: "Close as expected", min: "analyst", run: close("closed as expected") },
        ],
      };
    case "signature_feed": {
      const rule = i.rule_ids.find((r) => r.startsWith("FEED-"));
      return {
        actions: [
          { label: "Close as blocked", min: "analyst", run: close("closed: the call was blocked") },
          { label: "Open feed rule", href: rule ? `/threats?rule=${encodeURIComponent(rule)}` : "/threats" },
        ],
      };
    }
    case "policy_change": {
      const prev = previousPolicyVersion(i);
      return {
        actions: [
          { label: "View diff", href: "/policies?tab=history" },
          { label: prev ? `Roll back to ${prev}…` : "Roll back…", href: "/policies?tab=history" },
          { label: "Close as intended", min: "analyst", run: close("closed: change was intended") },
        ],
      };
    }
    case "break_glass":
      return {
        actions: [
          { label: "Acknowledge", min: "analyst", run: close("acknowledged", "Acknowledged") },
          {
            label: "Flag as inappropriate",
            min: "analyst",
            run: async () => {
              await patch.mutateAsync({ id: i.id, status: "triaged", note: "flagged as inappropriate" });
              return { title: "Flagged", text: "The incident stays open as triaged with your flag in the timeline." };
            },
          },
        ],
      };
    default:
      return { actions: [{ label: "Close", min: "analyst", run: close("closed") }] };
  }
}

function ReapproveForm({ incident, onDone, onCancel }: { incident: Incident; onDone: (r: { title: string; text: string }) => void; onCancel: () => void }) {
  const ev = rugPullOf(incident)!;
  const approve = useApproveTool();
  const patch = usePatchIncident();
  const [prefix, setPrefix] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const expected = (ev.newHash ?? "").slice(0, 4);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!reason.trim()) return setError("Write a reason.");
    if (!expected || prefix.trim().toLowerCase() !== expected.toLowerCase()) return setError("The first 4 characters of the new hash do not match.");
    setError(null);
    try {
      await approve.mutateAsync({ toolId: ev.toolId, reason: reason.trim() });
      await patch.mutateAsync({ id: incident.id, status: "resolved", note: `re-approved ${ev.tool} at ${shortHash(ev.newHash ?? "")}: ${reason.trim()}` });
      onDone({ title: "Re-approved", text: `${ev.tool} is pinned to the new version and shows up in clients again. The incident is resolved.` });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not re-approve.");
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-2 rounded-[6px] border border-border bg-raised p-2.5" aria-label="Re-approve new version">
      <label className="flex flex-col gap-1 text-[12px] text-muted">
        First 4 characters of the new hash ({shortHash(ev.newHash ?? "")})
        <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} className="font-mono" maxLength={4} />
      </label>
      <label className="flex flex-col gap-1 text-[12px] text-muted">
        Reason
        <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. vendor confirmed the change" />
      </label>
      {error && (
        <span role="alert" className="text-[12px] text-dec-block">
          {error}
        </span>
      )}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={approve.isPending || patch.isPending}>
          Re-approve
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function IncidentActions({ incident, onChanged }: { incident: Incident; onChanged: (id: string) => void }) {
  const { actions, note } = useActions(incident);
  const isAnalyst = useHasRole("analyst");
  const isAdmin = useHasRole("admin");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<{ title: string; text: string } | null>(null);
  const [error, setError] = React.useState<{ label: string; message: string } | null>(null);
  const [form, setForm] = React.useState<ActionDef["form"] | null>(null);

  const allowed = (min?: Role) => !min || (min === "admin" ? isAdmin : min === "analyst" ? isAnalyst : true);

  async function run(a: ActionDef) {
    if (!a.run) return;
    setBusy(a.label);
    setError(null);
    setResult(null);
    try {
      const r = await a.run();
      setResult(r);
      onChanged(incident.id);
    } catch (err) {
      setError({ label: a.label, message: err instanceof Error ? err.message : "Request failed" });
    } finally {
      setBusy(null);
    }
  }

  return (
    <SidebarSection title="Do something">
      <div className="flex flex-wrap gap-2">
        {actions.map((a, idx) => {
          const variant = idx === 0 ? "primary" : "secondary";
          if (a.href) {
            return (
              <Button key={a.label} asChild variant={variant} className="min-h-[34px]">
                <Link href={a.href}>{a.label}</Link>
              </Button>
            );
          }
          const roleBlocked = !allowed(a.min);
          const title = a.disabled ?? (roleBlocked ? `Needs the ${a.min} role` : undefined);
          return (
            <Button
              key={a.label}
              variant={variant}
              className="min-h-[34px]"
              disabled={!!a.disabled || roleBlocked || busy !== null}
              title={title}
              onClick={() => {
                if (a.form) setForm(form === a.form ? null : a.form);
                else void run(a);
              }}
            >
              {a.label}
            </Button>
          );
        })}
      </div>
      {note && <span className="text-[12px] text-muted">{note}</span>}
      {form === "reapprove" && (
        <ReapproveForm
          incident={incident}
          onCancel={() => setForm(null)}
          onDone={(r) => {
            setForm(null);
            setResult(r);
            onChanged(incident.id);
          }}
        />
      )}
      {result && (
        <StatusBox variant="success" title={result.title}>
          {result.text}
        </StatusBox>
      )}
      {error && (
        <StatusBox variant="error" title={`Could not ${error.label.replace(/…$/, "").toLowerCase()}`}>
          {error.message}
        </StatusBox>
      )}
    </SidebarSection>
  );
}
