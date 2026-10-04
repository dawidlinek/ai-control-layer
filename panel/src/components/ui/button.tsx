import * as React from "react";
import { Slot } from "radix-ui";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/**
 * Button variants (HANDOFF section 3/4): primary, danger (solid red), secondary, ghost.
 * Always at least 32 px high; primary is 34 px (`size="lg"` = 36 px).
 */
export const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-[6px] border text-[12.5px] font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "border-accent bg-accent text-on-accent hover:brightness-110",
        danger: "border-dec-block bg-dec-block text-on-accent hover:brightness-110",
        secondary: "border-border bg-raised text-text hover:border-border-strong",
        ghost: "border-transparent bg-transparent text-text hover:bg-raised",
      },
      size: {
        md: "min-h-8 px-3",
        lg: "min-h-9 px-4 text-[13px] font-semibold",
        sm: "min-h-8 px-2.5",
        icon: "size-8 min-h-8 p-0",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps extends React.ComponentProps<"button">, VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export function Button({ className, variant, size, asChild = false, type, ...props }: ButtonProps) {
  const Comp = asChild ? Slot.Root : "button";
  return (
    <Comp
      data-slot="button"
      type={asChild ? undefined : (type ?? "button")}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}
