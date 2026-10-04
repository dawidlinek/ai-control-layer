"use client";

import * as React from "react";
import { Popover as Primitive } from "radix-ui";
import { cn } from "@/lib/utils";

export const Popover = Primitive.Root;
export const PopoverTrigger = Primitive.Trigger;
export const PopoverAnchor = Primitive.Anchor;

export function PopoverContent({
  className,
  sideOffset = 6,
  align = "start",
  ...props
}: React.ComponentProps<typeof Primitive.Content>) {
  return (
    <Primitive.Portal>
      <Primitive.Content
        data-slot="popover-content"
        sideOffset={sideOffset}
        align={align}
        className={cn(
          "rg-pop z-50 w-72 rounded-[10px] border border-border-strong bg-surface p-3 text-[14px] text-text shadow-[var(--shadow-pop)]",
          className,
        )}
        {...props}
      />
    </Primitive.Portal>
  );
}
