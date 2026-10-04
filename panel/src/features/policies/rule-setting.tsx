"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useQueryClient } from "@tanstack/react-query";
import { DecisionBadge, Segmented, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useHasRole } from "@/lib/auth/user-context";
import { cn } from "@/lib/utils";
import type { PolicyFileContent } from "@/lib/api/types";
import { formatClock } from "@/lib/format";
import { policyKeys, useDryRun, usePolicyVersions, useWritePolicyFile } from "./api";
import { errorMessage, impactSentence, isConflict, nextVersionLabel, pct, suiteOf, versionLabel } from "./helpers";
import {
  readInjectionThreshold,
  readSessionThreshold,
  withInjectionThreshold,
  withSessionThreshold,
  type PolicyRule,
  type SessionLevel,
} from "./rules";

const STEP = 0.05;
const MIN = 0.5;
const MAX = 0.95;
const round2 = (n: number) => Math.round(n * 100) / 100;

const noteSchema = z.object({ note: z.string().trim().min(1, "Write a short note for the history.") });
type NoteForm = z.infer<typeof noteSchema>;

/**
 * The editable "Setting" of a rule (SEC-PI-01 injection threshold, SEC-SESSION-01 session threshold) with the
 * "If you publish this" impact box (dry-run) and Publish → new policy version, shown inline.
 */
export function RuleSetting({ rule, file }: { rule: PolicyRule; file: PolicyFileContent }) {
  const canEdit = useHasRole("admin");
  const versions = usePolicyVersions();
  const qc = useQueryClient();
  const write = useWritePolicyFile();
  const [published, setPublished] = React.useState<string | null>(null);

  // Live values, read from the file.
  const injection = rule.setting === "injection_threshold" ? readInjectionThreshold(file.content) : null;
  const session = rule.setting === "session_threshold" ? readSessionThreshold(file.content) : null;
  const liveKey = injection ? injection.value.toFixed(2) : (session ?? "");

  const [threshold, setThreshold] = React.useState(injection?.value ?? 0.8);
  const [level, setLevel] = React.useState<SessionLevel>(session ?? "confidential");
  // When the live value changes (publish, reload), the draft follows it.
  React.useEffect(() => {
    if (injection) setThreshold(injection.value);
    if (session) setLevel(session);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveKey]);

  const candidate = React.useMemo(() => {
    if (injection && round2(threshold) !== round2(injection.value)) return withInjectionThreshold(file.content, injection.preset, threshold);
    if (session && level !== session) return withSessionThreshold(file.content, rule.id, level);
    return null;
  }, [file.content, injection, session, threshold, level, rule.id]);

  const dry = useDryRun(file.name, candidate, canEdit && candidate !== null);
  const form = useForm<NoteForm>({ resolver: zodResolver(noteSchema), defaultValues: { note: "" } });
  const next = nextVersionLabel(versions.data);

  if (!injection && !session) return null;

  const change = (fn: () => void) => {
    setPublished(null);
    write.reset();
    fn();
  };
  const discard = () =>
    change(() => {
      if (injection) setThreshold(injection.value);
      if (session) setLevel(session);
      form.reset();
    });

  const publish = form.handleSubmit((v) => {
    if (!candidate) return;
    write.mutate(
      { name: file.name, content: candidate, baseVersion: file.version, message: v.note.trim() },
      {
        onSuccess: (status) => {
          setPublished(versionLabel(status.version, versions.data));
          form.reset();
        },
      },
    );
  });

  const reload = () => {
    write.reset();
    void qc.invalidateQueries({ queryKey: policyKeys.file(file.name) });
  };

  const readOnlyTitle = canEdit ? undefined : "Only admins can change policy";
  const r = dry.data;
  const suite = r ? suiteOf(r) : null;
  const dryErrors = r?.errors ?? [];

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-2.5 text-[13px]">
        {injection ? (
          <>
            <span>Block when the injection score is at least</span>
            <span className="inline-flex items-stretch overflow-hidden rounded-[6px] border border-border-strong">
              <button
                type="button"
                aria-label="Lower"
                title={readOnlyTitle}
                disabled={!canEdit || round2(threshold - STEP) < MIN}
                onClick={() => change(() => setThreshold((t) => round2(t - STEP)))}
                className="w-8 border-0 border-r border-border bg-raised text-text disabled:opacity-50"
              >
                −
              </button>
              <output
                aria-label="Injection threshold"
                className={cn("inline-flex items-center px-3 font-mono font-semibold", candidate && "bg-accent-soft")}
              >
                {threshold.toFixed(2)}
              </output>
              <button
                type="button"
                aria-label="Raise"
                title={readOnlyTitle}
                disabled={!canEdit || round2(threshold + STEP) > MAX}
                onClick={() => change(() => setThreshold((t) => round2(t + STEP)))}
                className="w-8 border-0 border-l border-border bg-raised text-text disabled:opacity-50"
              >
                +
              </button>
            </span>
            <span className="text-[12px] text-muted">
              live {injection.value.toFixed(2)} · preset {injection.preset}
            </span>
          </>
        ) : (
          <>
            <span>Keep a session on local models once it is</span>
            <span title={readOnlyTitle} className={cn(!canEdit && "pointer-events-none opacity-60")}>
              <Segmented
                ariaLabel="Session threshold"
                value={level}
                onChange={(v) => canEdit && change(() => setLevel(v))}
                options={[
                  { value: "confidential", label: "confidential" },
                  { value: "restricted", label: "restricted" },
                ]}
              />
            </span>
            <span className="text-[12px] text-muted">live {session}</span>
          </>
        )}
      </div>
      {!canEdit && <p className="m-0 text-[12px] text-muted">Only admins can change policy. You can read the setting and its history.</p>}

      {canEdit && candidate && (
        <form
          onSubmit={publish}
          aria-label="If you publish this"
          className="flex flex-col gap-2 rounded-[8px] border border-accent-line bg-inset p-3"
          noValidate
        >
          <b className="text-[12.5px] font-semibold">If you publish this</b>
          {dry.isPending && <span className="text-[12.5px] text-muted">Replaying the last 500 requests against the change…</span>}
          {dry.isError && (
            <StatusBox variant="error" title="Could not check the impact">
              {errorMessage(dry.error)}
            </StatusBox>
          )}
          {r && dryErrors.length > 0 && (
            <StatusBox variant="error" title="This change is not valid">
              {dryErrors.map((e) => e.message).join("; ")}
            </StatusBox>
          )}
          {r && dryErrors.length === 0 && (
            <>
              <p className={cn("m-0 text-[13px] leading-[1.45]", dry.isFetching && "opacity-60")}>{impactSentence(r)}</p>
              {suite && (
                <dl className="m-0 grid grid-cols-[minmax(0,1fr)_max-content] gap-x-3 gap-y-1 text-[12.5px]">
                  <dt className="text-muted">Attacks that get through</dt>
                  <dd className="m-0 font-mono">
                    {pct(suite.asrBefore)} →{" "}
                    <b className={cn("font-semibold", suite.asrAfter > suite.asrBefore ? "text-dec-block" : "text-dec-allow")}>{pct(suite.asrAfter)}</b>
                  </dd>
                  <dt className="text-muted">False alarms per request</dt>
                  <dd className="m-0 font-mono">
                    {pct(suite.fprBefore)} →{" "}
                    <b className={cn("font-semibold", suite.fprAfter > suite.fprBefore ? "text-dec-block" : "text-dec-allow")}>{pct(suite.fprAfter)}</b>
                  </dd>
                  <dt className="text-muted">Tests</dt>
                  <dd className="m-0 font-mono">
                    {suite.testsPassed === suite.testsTotal
                      ? `${suite.testsPassed} / ${suite.testsTotal} tests pass`
                      : `${suite.testsPassed} / ${suite.testsTotal} pass · ${suite.testsTotal - suite.testsPassed} known attacks now get through`}
                  </dd>
                </dl>
              )}
              {r.samples.length > 0 && (
                <ul aria-label="Requests that would change" className="m-0 flex list-none flex-col gap-1 p-0 text-[12px]">
                  {r.samples.slice(0, 3).map((s) => (
                    <li key={s.event_id} className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-muted">{formatClock(s.timestamp)}</span>
                      <span>{s.subject ?? "someone"}</span>
                      <DecisionBadge decision={s.before_action} />
                      <span aria-hidden className="text-muted">
                        →
                      </span>
                      <span className="sr-only">would become</span>
                      <DecisionBadge decision={s.after_action} />
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          <Input aria-label="Note for history" placeholder="Note for history (required)" className="bg-surface" {...form.register("note")} />
          {form.formState.errors.note && (
            <span role="alert" className="text-[12px] text-dec-block">
              {form.formState.errors.note.message}
            </span>
          )}
          {write.isError &&
            (isConflict(write.error) ? (
              <StatusBox variant="error" title={`${file.name} changed since you opened it`}>
                Someone saved a newer version while you were looking. Reload to see the latest file and check the impact again; Rogatka never
                overwrites a newer version.
                <div className="mt-2">
                  <Button size="sm" onClick={reload}>
                    Reload and check again
                  </Button>
                </div>
              </StatusBox>
            ) : (
              <StatusBox variant="error" title="Could not publish">
                {errorMessage(write.error)}
              </StatusBox>
            ))}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" className="border-border" onClick={discard}>
              Discard
            </Button>
            <Button type="submit" variant="primary" disabled={write.isPending || dry.isPending || dryErrors.length > 0}>
              {write.isPending ? "Publishing…" : next ? `Publish as ${next}` : "Publish"}
            </Button>
          </div>
        </form>
      )}

      {published && !candidate && (
        <StatusBox variant="success" title={`${published} is live`}>
          Saved as policy {published} · new requests use it now.
        </StatusBox>
      )}
    </div>
  );
}
