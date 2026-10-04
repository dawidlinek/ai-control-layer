import * as React from "react";
import { Slot } from "radix-ui";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/**
 * Button variants (STYLEGUIDE section 5): primary = ink fill (inverted in dark), secondary = 1 px strong border,
 * danger = `accent-text` fill with white label (Deny only), ghost. No red primary buttons: red means block.
 * Always at least 34 px high (`size="lg"` = 38 px).
 */
export const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-[6px] border text-[13.5px] font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "border-ink bg-ink text-on-ink hover:opacity-85",
        danger: "border-accent-text bg-accent-text text-on-accent hover:border-accent-pressed hover:bg-accent-pressed",
        secondary: "border-border-strong bg-surface text-text hover:bg-raised",
        ghost: "border-transparent bg-transparent text-text hover:bg-raised",
      },
      size: {
        md: "min-h-[34px] px-3.5",
        lg: "min-h-[38px] px-4 text-[14px] font-semibold",
        sm: "min-h-[34px] px-2.5",
        icon: "size-[34px] min-h-[34px] p-0",
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
