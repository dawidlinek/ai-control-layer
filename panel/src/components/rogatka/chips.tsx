import * as React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import {
  DECISION_ICON,
  DECISION_VAR,
  SEVERITY_ICON,
  SEVERITY_VAR,
  toSeverity,
  type Decision,
  type Severity,
} from "@/lib/decisions";
import { ICON_PATHS, PathIcon } from "./icon";

type ChipSize = "sm" | "md" | "lg";

const CHIP_SIZE: Record<ChipSize, { cls: string; icon: number; stroke: number }> = {
  // sm: table rows. md: sidebars. lg: overview legend.
  sm: { cls: "gap-1 rounded-[4px] py-0 pl-1 pr-1.5 text-[11px]", icon: 11, stroke: 2.4 },
  md: { cls: "gap-[5px] rounded-[5px] py-px pl-[5px] pr-2 text-[12px]", icon: 13, stroke: 2.2 },
  lg: { cls: "gap-[5px] rounded-[5px] py-px pl-[5px] pr-[7px] text-[11.5px]", icon: 12, stroke: 2.2 },
};

/**
 * Decision as icon + mono label (never colour alone). Tint style: text = decision colour,
 * background 14% (dark) / 10% (light), border 32% / 30%.
 */
export function DecisionBadge({
  decision,
  size = "sm",
  className,
  children,
}: {
  decision: Decision;
  size?: ChipSize;
  className?: string;
  /** Optional trailing content, e.g. a count in the Overview legend. */
  children?: React.ReactNode;
}) {
  const s = CHIP_SIZE[size];
  return (
    <span
      data-decision={decision}
      className={cn("tint inline-flex items-center whitespace-nowrap font-mono", s.cls, className)}
      style={{ "--c": DECISION_VAR[decision] } as React.CSSProperties}
    >
      <PathIcon path={DECISION_ICON[decision]} size={s.icon} strokeWidth={s.stroke} />
      {decision}
      {children}
    </span>
  );
}

/** A wrapped list of decision badges (a request can have several, e.g. pseudonymise + route_local). */
export function DecisionChips({
  decisions,
  size = "sm",
  className,
}: {
  decisions: readonly Decision[];
  size?: ChipSize;
  className?: string;
}) {
  if (decisions.length === 0) return <span className="text-muted">—</span>;
  return (
    <span className={cn("flex flex-wrap gap-1", size !== "sm" && "gap-1.5", className)}>
      {decisions.map((d, i) => (
        <DecisionBadge key={`${d}-${i}`} decision={d} size={size} />
      ))}
    </span>
  );
}

/** Severity chip: critical / high / medium / low, icon + label. `info` renders as low. */
export function SeverityChip({
  severity,
  size = "sm",
  className,
}: {
  severity: Severity | "info" | string;
  size?: ChipSize;
  className?: string;
}) {
  const sev = toSeverity(severity);
  const s = CHIP_SIZE[size];
  return (
    <span
      data-severity={sev}
      className={cn("tint inline-flex items-center whitespace-nowrap font-mono", s.cls, className)}
      style={{ "--c": SEVERITY_VAR[sev] } as React.CSSProperties}
    >
      <PathIcon path={SEVERITY_ICON[sev]} size={s.icon} strokeWidth={s.stroke} />
      {sev}
    </span>
  );
}

const ruleChipClass =
  "inline-flex items-center gap-1 rounded-[4px] border border-border-strong bg-raised px-[5px] font-mono text-[11px] leading-[1.5] text-text no-underline";

/**
 * Rule id chip: mono, raised background, strong border. Links to `/policies?rule=<ID>` unless `href={false}`.
 * `locked` adds a lock icon (org locks are read-only).
 */
export function RuleChip({
  ruleId,
  locked = false,
  href,
  className,
}: {
  ruleId: string;
  locked?: boolean;
  href?: string | false;
  className?: string;
}) {
  const body = (
    <>
      {locked && <PathIcon path={ICON_PATHS.lock} size={10} strokeWidth={2.2} aria-hidden={false} aria-label="Org lock" role="img" />}
      {ruleId}
    </>
  );
  if (href === false) {
    return (
      <span data-rule={ruleId} className={cn(ruleChipClass, className)}>
        {body}
      </span>
    );
  }
  return (
    <Link
      data-rule={ruleId}
      href={href ?? `/policies?rule=${encodeURIComponent(ruleId)}`}
      className={cn(ruleChipClass, "hover:border-accent", className)}
    >
      {body}
    </Link>
  );
}

/** `<PESEL_1>` style placeholder shown where a value was replaced. Uses the pseudonymise tint. */
export function PlaceholderChip({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      data-placeholder
      className={cn("tint inline-block rounded-[4px] px-[5px] py-px font-mono text-[12px]", className)}
      style={{ "--c": DECISION_VAR.pseudonymise } as React.CSSProperties}
    >
      {children}
    </span>
  );
}

/**
 * A masked identifier such as `PESEL ***-**-**123` or `PL** **** ... 2874`.
 * Only ever render values that are already masked: never pass raw sensitive data.
 */
export function MaskedValue({
  label,
  value,
  className,
}: {
  label?: string;
  value: string;
  className?: string;
}) {
  return (
    <span data-masked className={cn("whitespace-nowrap font-mono text-[12px]", className)} title="Masked value">
      {label && <span className="text-muted">{label} </span>}
      {value}
    </span>
  );
}

/** Toggle chip for allow lists: "✓ allowed" when on, "+ not" when off. */
export function ToggleChip({
  label,
  on,
  onChange,
  disabled,
  className,
}: {
  label: string;
  on: boolean;
  onChange?: (next: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange?.(!on)}
      className={cn(
        "inline-flex min-h-8 items-center gap-1.5 rounded-[6px] border px-2.5 text-[12.5px] disabled:opacity-60",
        on ? "border-accent-line bg-accent-soft text-text" : "border-border bg-surface text-muted hover:border-border-strong",
        className,
      )}
    >
      <span aria-hidden className={cn("font-mono", on && "text-accent")}>
        {on ? "✓" : "+"}
      </span>
      {label}
    </button>
  );
}

/** allow / deny / budget chip on a grant (allow and deny in the decision tints; budget neutral). */
export function EffectChip({ effect }: { effect: "allow" | "deny" | "budget" }) {
  const tint = effect === "allow" ? "var(--dec-allow)" : effect === "deny" ? "var(--dec-block)" : null;
  return (
    <span
      data-effect={effect}
      className={cn(
        "inline-flex shrink-0 rounded-[4px] px-1.5 font-mono text-[11px] leading-[1.6]",
        tint ? "tint" : "border border-border text-muted",
      )}
      style={tint ? ({ "--c": tint } as React.CSSProperties) : undefined}
    >
      {effect}
    </span>
  );
}

export type ToolStatus = "approved" | "quarantined" | "built-in" | "denied" | "not approved";

const TOOL_STATUS_TINT: Partial<Record<ToolStatus, string>> = {
  approved: "var(--dec-allow)",
  quarantined: "var(--dec-block)",
  "not approved": "var(--dec-require-approval)",
};

/** Tool status pill: tinted for approved / quarantined / not approved, outlined for built-in and denied. */
export function ToolStatusChip({ status }: { status: ToolStatus }) {
  const tint = TOOL_STATUS_TINT[status];
  return (
    <span
      data-status={status}
      className={cn(
        "inline-flex whitespace-nowrap rounded-full border px-2 py-px text-[12px]",
        tint ? "tint" : status === "denied" ? "border-border-strong text-muted" : "border-border text-text",
      )}
      style={tint ? ({ "--c": tint } as React.CSSProperties) : undefined}
    >
      {status}
    </span>
  );
}
