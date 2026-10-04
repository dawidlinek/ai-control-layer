"use client";

import * as React from "react";
import { Controller, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { SidebarBlock, SidebarHeader, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Textarea } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api/client";
import type { FeedRuleCreate, FeedRuleCreated } from "@/lib/api/types";
import { useAddFeedRule, useSignatures } from "./api";
import { nextLocalId, RULE_ACTIONS, RULE_SEVERITIES, RULE_TARGETS } from "./signatures";

/** Same pattern as the contract's `FeedRuleCreate.id`. */
export const RULE_ID_PATTERN = /^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$/;

const schema = z
  .object({
    id: z.string().trim().regex(RULE_ID_PATTERN, "Use capitals, digits and dashes, like FEED-LOCAL-0001."),
    description: z
      .string()
      .trim()
      .min(3, "Say what the rule catches (at least 3 characters).")
      .max(500, "Keep the description under 500 characters."),
    target: z.enum(RULE_TARGETS.map((t) => t.value) as [string, ...string[]]),
    ecosystem: z.enum(["pypi", "npm", "other"]),
    package: z.string().trim().max(200),
    versions: z.string(),
    pattern: z.string().trim().max(2000),
    tools: z.string(),
    severity: z.enum(RULE_SEVERITIES),
    action: z.enum(RULE_ACTIONS.map((a) => a.value) as [string, ...string[]]),
    atlas: z.string(),
    owasp: z.string(),
    cve: z.string(),
    source: z.string().trim().max(100, "Keep the source under 100 characters."),
    expires: z.string(),
    sync_now: z.boolean(),
  })
  .superRefine((v, ctx) => {
    if (v.target === "package") {
      if (!v.package) ctx.addIssue({ code: "custom", path: ["package"], message: "Enter the package name." });
    } else if (!v.pattern) {
      ctx.addIssue({ code: "custom", path: ["pattern"], message: v.target === "domain" ? "Enter the domain." : "Enter the pattern." });
    }
  });

type Values = z.infer<typeof schema>;

const list = (s: string): string[] =>
  s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

function defaults(id: string): Values {
  return {
    id,
    description: "",
    target: "package",
    ecosystem: "pypi",
    package: "",
    versions: "",
    pattern: "",
    tools: "",
    severity: "high",
    action: "block",
    atlas: "",
    owasp: "",
    cve: "",
    source: "panel",
    expires: "",
    sync_now: true,
  };
}

function toBody(v: Values): FeedRuleCreate {
  const body: FeedRuleCreate = {
    id: v.id,
    description: v.description,
    target: v.target as FeedRuleCreate["target"],
    severity: v.severity,
    action: v.action as FeedRuleCreate["action"],
    atlas_technique: list(v.atlas),
    owasp: list(v.owasp),
    cve: list(v.cve),
    source: v.source || "panel",
    expires: v.expires ? new Date(`${v.expires}T23:59:59`).toISOString() : null,
    sync_now: v.sync_now,
    // Only the package target reads it (the contract defaults it to pypi).
    ecosystem: v.target === "package" ? v.ecosystem : "pypi",
  };
  if (v.target === "package") {
    body.package = v.package;
    body.versions = list(v.versions);
  } else {
    body.pattern = v.pattern;
  }
  if (v.target === "command") body.tools = list(v.tools);
  return body;
}

/** What went wrong, in words, for the gateway's 409 / 422 / 502 / 503 answers. `field` puts the message under a field. */
export function describeAddError(e: unknown): { title: string; message: string; field?: "id" } {
  if (!(e instanceof ApiError)) return { title: "Could not add the rule", message: e instanceof Error ? e.message : "Unknown error." };
  switch (e.status) {
    case 409:
      return { title: "That ID is taken", message: e.detail || "A rule with this ID already exists.", field: "id" };
    case 422:
      return { title: "The rule is not valid", message: e.detail };
    case 502:
      return { title: "The feed server did not accept the rule", message: e.detail || "It is unreachable or rejected the request." };
    case 503:
      return { title: "Rule editing is not set up", message: e.detail || "This gateway has no feed server to publish rules to." };
    default:
      return { title: "Could not add the rule", message: e.detail };
  }
}

const field = "flex flex-col gap-1";

function FieldError({ children }: { children?: string }) {
  return children ? <span className="text-[12px] text-dec-block">{children}</span> : null;
}

/**
 * Add rule (flow F11): publishes a rule on the demo feed server, which stands in for the external signature system, and
 * (by default) asks the gateway to sync right away. Opens in the Signatures tab's sidebar (`?sel=new`), admin only.
 */
export function AddRuleForm() {
  const all = useSignatures();
  const add = useAddFeedRule();
  const [created, setCreated] = React.useState<FeedRuleCreated | null>(null);
  const [failure, setFailure] = React.useState<{ title: string; message: string } | null>(null);
  const ids = React.useMemo(() => (all.data ?? []).map((s) => s.id), [all.data]);

  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: defaults("FEED-LOCAL-0001") });
  const { register, control, handleSubmit, watch, reset, setError, setValue, formState } = form;
  const { errors, dirtyFields } = formState;
  const target = watch("target");
  const isPackage = target === "package";

  // Suggest the next free id once the list is there, unless the person already typed their own.
  React.useEffect(() => {
    if (all.data && !dirtyFields.id && !created) setValue("id", nextLocalId(ids));
  }, [all.data, ids, dirtyFields.id, created, setValue]);

  const submit = handleSubmit((v) => {
    setCreated(null);
    setFailure(null);
    add.mutate(toBody(v), {
      onSuccess: (res) => {
        setCreated(res);
        reset({ ...defaults(nextLocalId([...ids, res.rule.id])), severity: v.severity, action: v.action, source: v.source, sync_now: v.sync_now });
      },
      onError: (e) => {
        const d = describeAddError(e);
        if (d.field) setError(d.field, { type: "server", message: d.message });
        else setFailure({ title: d.title, message: d.message });
      },
    });
  });

  const idError = errors.id?.message;
  return (
    <>
      <SidebarHeader label="New rule" title="demo feed server" />
      <SidebarBlock>
        <p className="m-0 text-[13px] text-muted">
          Adds a rule to the demo feed server, which stands in for the external signature feed. The gateway picks it up on its next
          poll (every 30 s) or right away if you ask it to sync.
        </p>
        {created && (
          <StatusBox variant="success" title={`Added ${created.rule.id}`}>
            {created.bundle_version != null ? `feed bundle v${created.bundle_version}` : "feed bundle updated"} ·{" "}
            {created.synced ? "synced" : "not synced yet, the gateway polls every 30 s"}
          </StatusBox>
        )}
        {failure && (
          <StatusBox variant="error" title={failure.title}>
            {failure.message}
          </StatusBox>
        )}
        <form aria-label="Add rule" noValidate onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
          <div className={field}>
            <Label htmlFor="rule-id">Rule ID</Label>
            <Input
              id="rule-id"
              className="font-mono"
              aria-invalid={!!idError}
              aria-describedby={idError ? "rule-id-error" : undefined}
              {...register("id")}
            />
            <span id="rule-id-error">
              <FieldError>{idError}</FieldError>
            </span>
          </div>

          <div className={field}>
            <Label htmlFor="rule-description">What it catches</Label>
            <Textarea id="rule-description" rows={2} aria-invalid={!!errors.description} {...register("description")} />
            <FieldError>{errors.description?.message}</FieldError>
          </div>

          <div className={field}>
            <Label htmlFor="rule-target">Looks at</Label>
            <Controller
              control={control}
              name="target"
              render={({ field: f }) => (
                <Select value={f.value} onValueChange={f.onChange}>
                  <SelectTrigger id="rule-target" aria-label="Looks at">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RULE_TARGETS.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          {isPackage ? (
            <>
              <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-2.5">
                <div className={field}>
                  <Label htmlFor="rule-ecosystem">Ecosystem</Label>
                  <Controller
                    control={control}
                    name="ecosystem"
                    render={({ field: f }) => (
                      <Select value={f.value} onValueChange={f.onChange}>
                        <SelectTrigger id="rule-ecosystem" aria-label="Ecosystem">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="pypi">pypi</SelectItem>
                          <SelectItem value="npm">npm</SelectItem>
                          <SelectItem value="other">other</SelectItem>
                        </SelectContent>
                      </Select>
                    )}
                  />
                </div>
                <div className={field}>
                  <Label htmlFor="rule-package">Package</Label>
                  <Input id="rule-package" className="font-mono" placeholder="torchtriton" aria-invalid={!!errors.package} {...register("package")} />
                  <FieldError>{errors.package?.message}</FieldError>
                </div>
              </div>
              <div className={field}>
                <Label htmlFor="rule-versions">Versions</Label>
                <Input id="rule-versions" className="font-mono" placeholder="every version (or 1.82.7, 1.82.8)" {...register("versions")} />
              </div>
            </>
          ) : (
            <div className={field}>
              <Label htmlFor="rule-pattern">{target === "domain" ? "Domain (subdomains match)" : "Pattern (regular expression)"}</Label>
              <Input
                id="rule-pattern"
                className="font-mono"
                placeholder={target === "domain" ? "evil.example" : target === "command" ? "curl .*\\| *sh" : "(?i)ignore previous instructions"}
                aria-invalid={!!errors.pattern}
                {...register("pattern")}
              />
              <FieldError>{errors.pattern?.message}</FieldError>
            </div>
          )}

          {target === "command" && (
            <div className={field}>
              <Label htmlFor="rule-tools">Only for tools</Label>
              <Input id="rule-tools" className="font-mono" placeholder="all tools (or *bash*, *shell*)" {...register("tools")} />
            </div>
          )}

          <div className="grid grid-cols-2 gap-2.5">
            <div className={field}>
              <Label htmlFor="rule-severity">Severity</Label>
              <Controller
                control={control}
                name="severity"
                render={({ field: f }) => (
                  <Select value={f.value} onValueChange={f.onChange}>
                    <SelectTrigger id="rule-severity" aria-label="Severity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RULE_SEVERITIES.map((s) => (
                        <SelectItem key={s} value={s}>
                          {s}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
            <div className={field}>
              <Label htmlFor="rule-action">Action</Label>
              <Controller
                control={control}
                name="action"
                render={({ field: f }) => (
                  <Select value={f.value} onValueChange={f.onChange}>
                    <SelectTrigger id="rule-action" aria-label="Action">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RULE_ACTIONS.map((a) => (
                        <SelectItem key={a.value} value={a.value}>
                          {a.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
          </div>

          <details className="rounded-[6px] border border-border px-3 py-2 text-[13px]">
            <summary className="cursor-pointer select-none text-muted">Tags, source and expiry (optional)</summary>
            <div className="mt-2.5 flex flex-col gap-3">
              <div className="grid grid-cols-3 gap-2.5">
                <div className={field}>
                  <Label htmlFor="rule-atlas">ATLAS</Label>
                  <Input id="rule-atlas" className="font-mono" placeholder="AML.T0010" {...register("atlas")} />
                </div>
                <div className={field}>
                  <Label htmlFor="rule-owasp">OWASP</Label>
                  <Input id="rule-owasp" className="font-mono" placeholder="LLM03" {...register("owasp")} />
                </div>
                <div className={field}>
                  <Label htmlFor="rule-cve">CVE</Label>
                  <Input id="rule-cve" className="font-mono" placeholder="CVE-2025-0001" {...register("cve")} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <div className={field}>
                  <Label htmlFor="rule-source">Source</Label>
                  <Input id="rule-source" aria-invalid={!!errors.source} {...register("source")} />
                  <FieldError>{errors.source?.message}</FieldError>
                </div>
                <div className={field}>
                  <Label htmlFor="rule-expires">Expires</Label>
                  <Input id="rule-expires" type="date" {...register("expires")} />
                </div>
              </div>
            </div>
          </details>

          <div className="flex flex-wrap items-center gap-3">
            <Controller
              control={control}
              name="sync_now"
              render={({ field: f }) => (
                <span className="inline-flex items-center gap-2 text-[13px]">
                  <Checkbox id="rule-sync" checked={f.value} onCheckedChange={(c) => f.onChange(c === true)} />
                  <label htmlFor="rule-sync" className="cursor-pointer select-none">
                    Ask the gateway to sync now
                  </label>
                </span>
              )}
            />
            <div className="flex-1" />
            <Button type="submit" variant="primary" disabled={add.isPending}>
              {add.isPending ? "Publishing…" : "Publish rule"}
            </Button>
          </div>
        </form>
      </SidebarBlock>
    </>
  );
}
