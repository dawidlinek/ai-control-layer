"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Label, Textarea } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useHasRole } from "@/lib/auth/user-context";
import { formatNumber, formatUsd } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ConnectorStatus, ModelInfo } from "@/lib/api/types";
import { useKillSwitch, type KillSwitchResult } from "./api";
import { aliasesOf, connectorName, isGuardModel, joinAnd } from "./details";

const NOT_IN_API = "Not available in the admin API yet";

export interface KillSwitchNotice {
  connector: ConnectorStatus;
  aliases: string[];
  savedAs: string | null;
}

/** Page-level result of a kill switch (under the title, as in the prototype). */
export function KillSwitchMessage({ notice }: { notice: KillSwitchNotice }) {
  const { connector: c, aliases, savedAs } = notice;
  const name = connectorName(c.id);
  const what = aliases.length ? (
    <>
      Requests for <Aliases aliases={aliases} />
    </>
  ) : (
    <>Requests for its models</>
  );
  const saved = savedAs && (
    <>
      {" "}
      Saved as policy <b className="font-mono font-semibold">{savedAs}</b>.
    </>
  );
  if (!c.kill_switch) {
    return (
      <StatusBox variant="success">
        {name} is back on. {what} go to {name} again.{saved}
      </StatusBox>
    );
  }
  return (
    <StatusBox variant="warning">
      {name} is switched off. {what}{" "}
      {c.tier === "cloud"
        ? "now go to local models and their answers are marked as degraded."
        : "are refused until it is switched back on."}
      {saved}
    </StatusBox>
  );
}

function Aliases({ aliases }: { aliases: string[] }) {
  return (
    <>
      {aliases.map((a, i) => (
        <React.Fragment key={a}>
          {i > 0 && (i === aliases.length - 1 ? " and " : ", ")}
          <span className="font-mono">{a}</span>
        </React.Fragment>
      ))}
    </>
  );
}

function healthOf(c: ConnectorStatus): { label: string; dot: string } {
  if (c.kill_switch || !c.enabled) return { label: "off", dot: "bg-muted" };
  if (c.healthy === true) return { label: "healthy", dot: "bg-dec-allow" };
  if (c.healthy === false) return { label: "unreachable", dot: "bg-dec-block" };
  return { label: "unknown", dot: "bg-muted" };
}

function ConnectorCard({
  connector: c,
  models,
  onToggle,
}: {
  connector: ConnectorStatus;
  models: readonly ModelInfo[];
  onToggle: (c: ConnectorStatus) => void;
}) {
  const isAdmin = useHasRole("admin");
  const on = c.enabled && !c.kill_switch;
  const own = models.filter((m) => m.connector === c.id);
  const chatModels = own.filter((m) => !isGuardModel(m)).length;
  const name = connectorName(c.id);
  const health = healthOf(c);
  const today = c.tier === "cloud" ? `${formatUsd(c.spend_usd_day)} USD` : `${formatNumber(own.reduce((s, m) => s + m.gpu_seconds_day, 0))} GPU-s`;
  const switchId = `connector-${c.id}`;
  return (
    <section
      aria-label={`${name} connector`}
      className={cn("flex min-w-0 flex-[1_1_280px] flex-col gap-2.5 rounded-[8px] border border-border bg-surface px-4 py-3.5", !on && "opacity-70")}
    >
      <div className="flex items-center gap-2.5">
        <span className="flex min-w-0 flex-1 flex-col">
          <b className="text-[14px] font-semibold">{name}</b>
          <span className="truncate text-[12px] text-muted">
            {c.tier} · {chatModels} {chatModels === 1 ? "model" : "models"} · {c.type === "openai_compatible" ? "OpenAI-compatible API" : c.type}
          </span>
        </span>
        <label
          htmlFor={switchId}
          className="inline-flex min-h-8 cursor-pointer items-center gap-2 text-[13px]"
          title={isAdmin ? undefined : "Only admins can switch connectors on or off"}
        >
          <Switch
            id={switchId}
            aria-label={`${name} on`}
            checked={on}
            disabled={!isAdmin}
            onCheckedChange={() => onToggle(c)}
          />
          {on ? "On" : "Off"}
        </label>
      </div>
      <div className="grid grid-cols-3 gap-2 text-[13px]">
        <span className="flex min-w-0 flex-col">
          <span className="text-[11px] text-muted">Health</span>
          <span className="inline-flex items-center gap-1.5" title={c.last_error ?? undefined}>
            <span aria-hidden className={cn("size-[7px] rounded-full", health.dot)} />
            {health.label}
          </span>
        </span>
        <span className="flex min-w-0 flex-col">
          <span className="text-[11px] text-muted">Response time p50</span>
          <span className="font-mono">{on && c.latency_ms_p50 != null ? `${formatNumber(c.latency_ms_p50)} ms` : "—"}</span>
        </span>
        <span className="flex min-w-0 flex-col">
          <span className="text-[11px] text-muted">Today</span>
          <span className="font-mono">{today}</span>
        </span>
      </div>
    </section>
  );
}

export function ConnectorCards({
  connectors,
  models,
  onResult,
}: {
  connectors: readonly ConnectorStatus[];
  models: readonly ModelInfo[];
  onResult: (notice: KillSwitchNotice) => void;
}) {
  const [target, setTarget] = React.useState<ConnectorStatus | null>(null);
  return (
    <div className="flex flex-wrap gap-3">
      {connectors.map((c) => (
        <ConnectorCard key={c.id} connector={c} models={models} onToggle={setTarget} />
      ))}
      <button
        type="button"
        disabled
        title={`${NOT_IN_API}: connectors are added in models.yaml`}
        className="min-h-[100px] flex-[0_1_200px] cursor-not-allowed rounded-[8px] border border-dashed border-border-strong bg-transparent text-[13px] text-muted"
      >
        + Add connector
      </button>
      {target && (
        <KillSwitchDialog
          connector={target}
          aliases={aliasesOf(models, target.id)}
          onClose={() => setTarget(null)}
          onDone={(r) => {
            setTarget(null);
            onResult({ connector: r.connector, aliases: aliasesOf(models, r.connector.id), savedAs: r.savedAs });
          }}
        />
      )}
    </div>
  );
}

const reasonSchema = z.object({ reason: z.string().trim().min(1, "Write a reason. It is saved with the change.") });
type ReasonForm = z.infer<typeof reasonSchema>;

function KillSwitchDialog({
  connector: c,
  aliases,
  onClose,
  onDone,
}: {
  connector: ConnectorStatus;
  aliases: string[];
  onClose: () => void;
  onDone: (r: KillSwitchResult) => void;
}) {
  const kill = useKillSwitch();
  const name = connectorName(c.id);
  const engage = !c.kill_switch;
  const form = useForm<ReasonForm>({ resolver: zodResolver(reasonSchema), defaultValues: { reason: "" } });
  const error = form.formState.errors.reason?.message;
  const submit = form.handleSubmit((v) =>
    kill.mutate({ id: c.id, engaged: engage, reason: v.reason.trim() }, { onSuccess: onDone }),
  );
  const aliasText = aliases.length ? joinAnd(aliases) : "its models";
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogTitle>{engage ? `Switch off ${name}?` : `Switch ${name} back on?`}</DialogTitle>
        <DialogDescription>
          {engage
            ? c.tier === "cloud"
              ? `Requests for ${aliasText} will go to local models and their answers will be marked as degraded.`
              : `Requests for ${aliasText} will be refused until it is switched back on.`
            : `Requests for ${aliasText} will go to ${name} again.`}{" "}
          This is a policy change.
        </DialogDescription>
        <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3" noValidate>
          <div className="flex flex-col gap-1">
            <Label htmlFor="kill-reason">Reason (required)</Label>
            <Textarea
              id="kill-reason"
              aria-invalid={!!error}
              aria-describedby={error ? "kill-reason-error" : undefined}
              placeholder={engage ? "e.g. provider incident, data residency check" : "e.g. provider incident resolved"}
              {...form.register("reason")}
            />
            {error && (
              <span id="kill-reason-error" className="text-[12px] text-dec-block">
                {error}
              </span>
            )}
          </div>
          {kill.isError && (
            <StatusBox variant="error" title={engage ? `Could not switch off ${name}` : `Could not switch on ${name}`}>
              {kill.error.message}
            </StatusBox>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant={engage ? "danger" : "primary"} disabled={kill.isPending}>
              {engage ? `Switch off ${name}` : `Switch on ${name}`}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
