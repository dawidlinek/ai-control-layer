"use client";

import * as React from "react";
import { Checkbox as Primitive } from "radix-ui";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

export function Checkbox({ className, ...props }: React.ComponentProps<typeof Primitive.Root>) {
  return (
    <Primitive.Root
      data-slot="checkbox"
      className={cn(
        "inline-flex size-4 shrink-0 items-center justify-center rounded-[4px] border border-border-strong bg-inset data-[state=checked]:border-ink data-[state=checked]:bg-ink data-[state=checked]:text-on-ink",
        className,
      )}
      {...props}
    >
      <Primitive.Indicator>
        <Check className="size-3" aria-hidden />
      </Primitive.Indicator>
    </Primitive.Root>
  );
}
