import * as React from "react";
import { ICON_PATHS, PathIcon, PlaceholderChip } from "@/components/rogatka";
import type { SessionLabelInfo } from "@/lib/api/types";
import { DECISION_VAR } from "@/lib/decisions";
import { cn } from "@/lib/utils";
import { sessionLabelText, splitPlaceholders } from "./model";

/** Text as Rogatka stored / the model saw it, with `<PESEL_1>`, `‹SECRET:api_key›`, `[removed: …]` as chips. */
export function RedactedText({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn("whitespace-pre-wrap break-words", className)}>
      {splitPlaceholders(text).map((p, i) =>
        p.placeholder ? <PlaceholderChip key={i}>{p.text}</PlaceholderChip> : <React.Fragment key={i}>{p.text}</React.Fragment>,
      )}
    </span>
  );
}

const labelStyle = { "--c": DECISION_VAR.route_local } as React.CSSProperties;

/** Small chip on Traffic rows whose session is confidential / restricted ("local only"). */
export function SessionLabelChip({ label, className }: { label: SessionLabelInfo; className?: string }) {
  const text = sessionLabelText(label);
  return (
    <span
      data-session-label={label.data_class}
      title={text}
      aria-label={text}
      className={cn("tint inline-flex items-center gap-1 whitespace-nowrap rounded-[4px] py-0 pl-1 pr-1.5 font-mono text-[11px]", className)}
      style={labelStyle}
    >
      <PathIcon path={ICON_PATHS.lock} size={10} strokeWidth={2.2} />
      {label.data_class}
    </span>
  );
}

/** One-line session label in the trace sidebar and the session view header (HANDOFF 7.2). */
export function SessionLabelLine({ label, className }: { label: SessionLabelInfo; className?: string }) {
  return (
    <div
      data-session-label={label.data_class}
      className={cn("tint flex items-center gap-2 rounded-[6px] px-2.5 py-1.5 text-[13px]", className)}
      style={labelStyle}
    >
      <PathIcon path={ICON_PATHS.lock} size={13} />
      <span className="text-text">{sessionLabelText(label)}</span>
    </div>
  );
}
