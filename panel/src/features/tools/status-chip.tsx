import type * as React from "react";
import { cn } from "@/lib/utils";
import type { ToolRule, ToolStatus } from "./catalogue";

const TINT: Partial<Record<ToolStatus, string>> = {
  approved: "var(--dec-allow)",
  quarantined: "var(--dec-block)",
  "not approved": "var(--dec-require-approval)",
};

/** Tool status pill: tinted for approved / quarantined / not approved, outlined for built-in and denied. */
export function StatusChip({ status }: { status: ToolStatus }) {
  const tint = TINT[status];
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

const RULE_CLASS: Record<ToolRule, string> = {
  allowed: "text-muted",
  "needs approval": "text-dec-require-approval",
  denied: "text-dec-block",
  "—": "text-muted",
};

export function RuleText({ rule }: { rule: ToolRule }) {
  return <span className={RULE_CLASS[rule]}>{rule}</span>;
}
