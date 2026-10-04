import * as React from "react";
import { cn } from "@/lib/utils";

export interface DiffLine {
  sign: "+" | "-" | "~" | " ";
  text: string;
}

/**
 * Bordered mono box with a title bar and +/-/~ lines (git diff, terraform plan, tool description diff).
 * `addedTone="bad"` paints added lines red (injected text in a rug pull); default paints them green.
 * `removedTone="good"` paints removed lines green instead of red (the rug-pull case, where removed text is the clean text).
 * Without a `title` there is no title bar.
 */
export function DiffBox({
  title,
  lines,
  addedTone = "good",
  removedTone = "bad",
  ariaLabel,
  className,
}: {
  title?: React.ReactNode;
  lines: readonly DiffLine[];
  addedTone?: "good" | "bad";
  removedTone?: "good" | "bad";
  ariaLabel?: string;
  className?: string;
}) {
  const addVar = addedTone === "bad" ? "var(--dec-block)" : "var(--dec-allow)";
  const removeVar = removedTone === "good" ? "var(--dec-allow)" : "var(--dec-block)";
  const tone = (sign: DiffLine["sign"]) =>
    sign === "+" ? addVar : sign === "-" ? removeVar : sign === "~" ? "var(--dec-downgrade)" : null;
  return (
    <figure
      aria-label={ariaLabel}
      className={cn("m-0 overflow-hidden rounded-[6px] border border-border font-mono text-[12px] leading-[1.6]", className)}
    >
      {title != null && (
        <figcaption className="border-b border-border bg-raised px-2.5 py-[5px] font-sans text-[11.5px] text-muted">{title}</figcaption>
      )}
      <div className="rg-scroll overflow-x-auto">
        {lines.map((l, i) => {
          const c = tone(l.sign);
          return (
            <div
              key={i}
              data-sign={l.sign === " " ? "context" : l.sign}
              className="grid grid-cols-[16px_minmax(0,1fr)] px-2.5 py-px"
              style={c ? { background: `color-mix(in srgb, ${c} 12%, transparent)` } : undefined}
            >
              <span aria-hidden style={{ color: c ?? "var(--muted)" }}>
                {l.sign}
              </span>
              <span className="whitespace-pre-wrap break-words">{l.text}</span>
            </div>
          );
        })}
      </div>
    </figure>
  );
}
