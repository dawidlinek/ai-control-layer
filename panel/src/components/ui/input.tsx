import * as React from "react";
import { cn } from "@/lib/utils";

/** Text input on the `inset` surface, 32 px high. */
export function Input({ className, type = "text", ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "min-h-8 w-full min-w-0 rounded-[6px] border border-border bg-inset px-2.5 text-[12.5px] text-text placeholder:text-muted disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "min-h-16 w-full rounded-[6px] border border-border bg-inset px-2.5 py-1.5 text-[12.5px] text-text placeholder:text-muted disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: React.ComponentProps<"label">) {
  return <label data-slot="label" className={cn("text-[11px] text-muted", className)} {...props} />;
}
