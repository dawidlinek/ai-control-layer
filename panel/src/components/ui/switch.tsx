"use client";

import * as React from "react";
import { Switch as Primitive } from "radix-ui";
import { cn } from "@/lib/utils";

/** 30 x 18 track with a 12 px knob, as in the prototypes. */
export function Switch({ className, ...props }: React.ComponentProps<typeof Primitive.Root>) {
  return (
    <Primitive.Root
      data-slot="switch"
      className={cn(
        "relative inline-flex h-[18px] w-[30px] shrink-0 items-center rounded-full border border-border-strong bg-inset transition-colors data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <Primitive.Thumb className="block size-3 translate-x-[2px] rounded-full bg-muted transition-transform data-[state=checked]:translate-x-[14px] data-[state=checked]:bg-on-accent" />
    </Primitive.Root>
  );
}
