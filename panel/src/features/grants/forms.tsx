"use client";

import * as React from "react";
import { Controller, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Segmented, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import type { Grant } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { useCreateGrant } from "./api";
import {
  ceilingCheck,
  DATA_CLASSES,
  expiresAtFor,
  isCloudResource,
  isModelFamily,
  itemLabel,
  LOCKED_FOR_CLOUD,
  parseResourceValue,
  RESOURCE_OPTIONS,
  type DataClass,
  type ExpiryChoice,
  type ResourceOption,
} from "./model";

const fieldLabel = "flex flex-col gap-1 text-[12px] text-muted";
export const selectClass =
  "min-h-[34px] w-full rounded-[6px] border border-border bg-inset px-2.5 text-[13px] text-text disabled:opacity-50";

const grantSchema = z
  .object({
    subject: z.string().min(1, "Choose a person or a group"),
    resource: z.string().min(1, "Choose what to grant"),
    effect: z.enum(["allow", "deny"]),
    dataClasses: z.array(z.enum(["public", "internal", "confidential", "restricted"])),
    expiry: z.enum(["1 d", "7 d", "30 d", "never"]),
    reason: z.string().trim().min(3, "A reason is required (at least 3 characters).").max(500, "Keep the reason under 500 characters."),
  })
  .superRefine((v, ctx) => {
    if (v.effect === "allow" && v.resource && isModelFamily(parseResourceValue(v.resource).type) && v.dataClasses.length === 0) {
      ctx.addIssue({ code: "custom", path: ["dataClasses"], message: "Pick at least one data class." });
    }
  });

export type GrantFormValues = z.infer<typeof grantSchema>;

export interface GrantFormDefaults {
  subject?: string;
  resource?: string;
  effect?: "allow" | "deny";
  dataClasses?: DataClass[];
  expiry?: ExpiryChoice;
  reason?: string;
}

/**
 * Grant form (react-hook-form + zod). `variant="person"`: the inline form in a person's Access list (subject fixed,
 * allow only, expiry 1 / 7 / 30 days, locked classes shown disabled). `variant="full"`: the Grants sidebar
 * "New grant" form (person or group, effect, expiry incl. never) with the LOCK-01 ceiling check.
 * Posts `/admin/v1/grants`; `onCreated` receives the new grant (the parent shows the inline result).
 */
export function GrantForm({
  variant,
  defaults,
  subjects = [],
  resourceOptions = RESOURCE_OPTIONS,
  personName,
  onCreated,
  onCancel,
}: {
  variant: "person" | "full";
  defaults?: GrantFormDefaults;
  /** Full variant: `user:<username>` / `group:<name>` options. */
  subjects?: readonly { value: string; label: string }[];
  resourceOptions?: readonly ResourceOption[];
  /** Person variant: first name for the title ("Give Jan access to ..."). */
  personName?: string;
  onCreated?: (grant: Grant) => void;
  onCancel: () => void;
}) {
  const create = useCreateGrant();
  const isPerson = variant === "person";
  const form = useForm<GrantFormValues>({
    resolver: zodResolver(grantSchema),
    defaultValues: {
      subject: defaults?.subject ?? "",
      resource: defaults?.resource ?? resourceOptions[0]?.value ?? "",
      effect: defaults?.effect ?? "allow",
      dataClasses: defaults?.dataClasses ?? ["public", "internal"],
      expiry: defaults?.expiry ?? "7 d",
      reason: defaults?.reason ?? "",
    },
  });
  const { register, control, handleSubmit, watch, formState } = form;
  const values = watch();
  const { type, resource } = values.resource ? parseResourceValue(values.resource) : { type: "alias" as const, resource: "" };
  const showClasses = isModelFamily(type) && values.effect === "allow";
  const cloud = isCloudResource(resource);
  const check = ceilingCheck({ effect: values.effect, resourceType: type, resource, dataClasses: showClasses ? values.dataClasses : [] });
  const ids = React.useId();

  const onSubmit = handleSubmit((v) => {
    const subj = v.subject.split(":");
    const r = parseResourceValue(v.resource);
    const withClasses = isModelFamily(r.type) && v.effect === "allow";
    create.mutate(
      {
        subject_type: subj[0] === "group" ? "group" : "user",
        subject: subj.slice(1).join(":"),
        resource_type: r.type,
        resource: r.resource,
        effect: v.effect,
        constraints: withClasses ? { data_classes: v.dataClasses } : {},
        expires_at: expiresAtFor(v.expiry),
        reason: v.reason.trim(),
      },
      { onSuccess: (g) => onCreated?.(g) },
    );
  });

  const expiryOptions: ExpiryChoice[] = isPerson ? ["1 d", "7 d", "30 d"] : ["1 d", "7 d", "30 d", "never"];

  return (
    <form
      aria-label={isPerson ? "Grant access" : "New grant"}
      noValidate
      onSubmit={(e) => void onSubmit(e)}
      className={cn("flex flex-col gap-3", isPerson && "mt-1 rounded-[8px] border border-accent-line bg-inset p-3")}
    >
      {isPerson && (
        <b className="text-[13px] font-semibold">
          Give {personName ?? "them"} access to <span className="font-mono">{itemLabel(type, resource)}</span>
        </b>
      )}

      {!isPerson && (
        <label className={fieldLabel}>
          Person or group
          <select {...register("subject")} className={selectClass} aria-invalid={!!formState.errors.subject}>
            <option value="">Choose…</option>
            {subjects.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          {formState.errors.subject && <span className="text-dec-block">{formState.errors.subject.message}</span>}
        </label>
      )}

      {(!isPerson || resourceOptions.length > 1) && (
        <label className={fieldLabel}>
          What
          <select {...register("resource")} className={selectClass}>
            {resourceOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      )}

      {!isPerson && (
        <div className={fieldLabel}>
          Effect
          <Controller
            control={control}
            name="effect"
            render={({ field }) => (
              <Segmented
                ariaLabel="Effect"
                className="self-start"
                value={field.value}
                onChange={field.onChange}
                options={[
                  { value: "allow", label: "Allow" },
                  { value: "deny", label: "Deny" },
                ]}
              />
            )}
          />
        </div>
      )}

      {showClasses && (
        <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0 text-[12px] text-muted">
          <legend className="mb-1.5 p-0">Data classes</legend>
          <Controller
            control={control}
            name="dataClasses"
            render={({ field }) => (
              <div className="flex flex-wrap gap-1.5">
                {DATA_CLASSES.map((c) => {
                  const locked = cloud && (LOCKED_FOR_CLOUD as readonly string[]).includes(c);
                  if (isPerson && locked) {
                    return (
                      <span key={c} className="inline-flex min-h-7 items-center gap-1 rounded-[6px] border border-border px-2 font-mono text-[12px] text-muted" title="LOCK-01: never to cloud models">
                        × {c} · LOCK-01
                      </span>
                    );
                  }
                  const id = `${ids}-${c}`;
                  const on = field.value.includes(c);
                  return (
                    <label
                      key={c}
                      htmlFor={id}
                      className={cn(
                        "inline-flex min-h-7 cursor-pointer items-center gap-1.5 rounded-[6px] border px-2 font-mono text-[12px]",
                        on ? "border-accent-line bg-accent-soft text-text" : "border-border text-muted",
                      )}
                    >
                      <Checkbox
                        id={id}
                        checked={on}
                        onCheckedChange={(next) => field.onChange(next ? [...field.value, c] : field.value.filter((x) => x !== c))}
                      />
                      {c}
                    </label>
                  );
                })}
              </div>
            )}
          />
          {formState.errors.dataClasses && <span className="text-dec-block">{formState.errors.dataClasses.message}</span>}
        </fieldset>
      )}

      <div className={cn(fieldLabel, isPerson && "flex-row items-center gap-2.5")}>
        Expires
        <Controller
          control={control}
          name="expiry"
          render={({ field }) => (
            <Segmented
              ariaLabel="Expiry"
              className="self-start"
              value={field.value}
              onChange={field.onChange}
              options={expiryOptions.map((e) => ({ value: e, label: e }))}
            />
          )}
        />
      </div>

      <label className={fieldLabel}>
        Reason (required)
        <Input
          {...register("reason")}
          placeholder={isPerson ? "e.g. Gemini pilot" : "Why does this person need it?"}
          aria-invalid={!!formState.errors.reason}
          className="min-h-[34px] text-[13px]"
        />
        {formState.errors.reason && <span className="text-dec-block">{formState.errors.reason.message}</span>}
      </label>

      {!isPerson && (
        <StatusBox variant={check.ok ? "success" : "error"} title={check.ok ? undefined : "Above the org-lock ceiling"}>
          {check.message}
        </StatusBox>
      )}
      {isPerson && cloud && <p className="m-0 text-[12px] text-muted">Confidential and restricted data never go to cloud models (LOCK-01).</p>}

      {create.isError && (
        <StatusBox variant="error" title="Could not create the grant">
          {create.error.message}
        </StatusBox>
      )}

      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel} className="border-border">
          Cancel
        </Button>
        <Button type="submit" variant="primary" disabled={create.isPending || !check.ok}>
          {isPerson ? "Grant access" : "Create grant"}
        </Button>
      </div>
    </form>
  );
}

const reasonSchema = z.object({
  reason: z.string().trim().min(3, "A reason is required (at least 3 characters).").max(500, "Keep the reason under 500 characters."),
});

/**
 * Inline confirm with a required reason, used for Revoke / Remove denial / Restore (DELETE /grants/{id}?reason=)
 * and for "Revoke" of a group tool for one person (creates a deny grant).
 */
export function ReasonForm({
  title,
  submitLabel,
  danger = true,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  title: React.ReactNode;
  submitLabel: string;
  danger?: boolean;
  pending?: boolean;
  error?: Error | null;
  onSubmit: (reason: string) => void;
  onCancel: () => void;
}) {
  const form = useForm<z.infer<typeof reasonSchema>>({ resolver: zodResolver(reasonSchema), defaultValues: { reason: "" } });
  const err = form.formState.errors.reason;
  return (
    <form
      aria-label={submitLabel}
      noValidate
      onSubmit={(e) => void form.handleSubmit((v) => onSubmit(v.reason.trim()))(e)}
      className="flex flex-col gap-2.5 rounded-[8px] border border-border-strong bg-inset p-3"
    >
      <b className="text-[13px] font-semibold">{title}</b>
      <label className={fieldLabel}>
        Reason (required)
        <Input {...form.register("reason")} aria-invalid={!!err} className="min-h-[34px] text-[13px]" />
        {err && <span className="text-dec-block">{err.message}</span>}
      </label>
      {error && (
        <StatusBox variant="error" title="That did not work">
          {error.message}
        </StatusBox>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant={danger ? "danger" : "primary"} disabled={pending}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
