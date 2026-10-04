"use client";

import * as React from "react";
import { Tooltip as Primitive } from "radix-ui";
import { cn } from "@/lib/utils";

export const TooltipProvider = Primitive.Provider;
export const Tooltip = Primitive.Root;
export const TooltipTrigger = Primitive.Trigger;

export function TooltipContent({
  className,
  sideOffset = 6,
  ...props
}: React.ComponentProps<typeof Primitive.Content>) {
  return (
    <Primitive.Portal>
      <Primitive.Content
        sideOffset={sideOffset}
        className={cn(
          "z-50 rounded-[6px] border border-border-strong bg-raised px-2 py-1 text-[12px] text-text shadow-[var(--shadow-pop)]",
          className,
        )}
        {...props}
      />
    </Primitive.Portal>
  );
}
