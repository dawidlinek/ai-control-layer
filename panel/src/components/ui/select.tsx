"use client";

import * as React from "react";
import { Select as Primitive } from "radix-ui";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

export const Select = Primitive.Root;
export const SelectGroup = Primitive.Group;
export const SelectValue = Primitive.Value;

/** Closed state: same look as the inset form fields (`min-h-[34px]`, 6 px radius). */
export function SelectTrigger({ className, children, ...props }: React.ComponentProps<typeof Primitive.Trigger>) {
  return (
    <Primitive.Trigger
      data-slot="select-trigger"
      className={cn(
        "inline-flex min-h-[34px] w-full items-center justify-between gap-2 rounded-[6px] border border-border-strong bg-inset px-2.5 text-left text-[14px] text-text",
        "data-[placeholder]:text-muted data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 aria-[invalid=true]:border-dec-block",
        className,
      )}
      {...props}
    >
      <span className="min-w-0 truncate">{children}</span>
      <Primitive.Icon asChild>
        <ChevronDown className="size-3.5 shrink-0 text-muted" aria-hidden />
      </Primitive.Icon>
    </Primitive.Trigger>
  );
}

export function SelectContent({
  className,
  children,
  position = "popper",
  sideOffset = 4,
  ...props
}: React.ComponentProps<typeof Primitive.Content>) {
  return (
    <Primitive.Portal>
      <Primitive.Content
        data-slot="select-content"
        position={position}
        sideOffset={sideOffset}
        className={cn(
          "rg-pop z-50 max-h-[var(--radix-select-content-available-height)] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-[10px] border border-border-strong bg-surface text-[14px] text-text shadow-[var(--shadow-pop)]",
          className,
        )}
        {...props}
      >
        <Primitive.Viewport className="rg-scroll p-1.5">{children}</Primitive.Viewport>
      </Primitive.Content>
    </Primitive.Portal>
  );
}

export function SelectItem({ className, children, ...props }: React.ComponentProps<typeof Primitive.Item>) {
  return (
    <Primitive.Item
      data-slot="select-item"
      className={cn(
        "relative flex min-h-9 cursor-pointer select-none items-center rounded-[6px] py-0 pl-8 pr-2.5 text-[14px] outline-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[highlighted]:bg-raised",
        className,
      )}
      {...props}
    >
      <span className="absolute left-2.5 flex size-4 items-center justify-center">
        <Primitive.ItemIndicator>
          <Check className="size-3.5 text-text" aria-hidden />
        </Primitive.ItemIndicator>
      </span>
      <Primitive.ItemText>{children}</Primitive.ItemText>
    </Primitive.Item>
  );
}

export function SelectLabel({ className, ...props }: React.ComponentProps<typeof Primitive.Label>) {
  return (
    <Primitive.Label
      className={cn("px-2.5 py-1.5 text-[11px] font-bold uppercase tracking-[.1em] text-muted", className)}
      {...props}
    />
  );
}

export function SelectSeparator({ className, ...props }: React.ComponentProps<typeof Primitive.Separator>) {
  return <Primitive.Separator className={cn("-mx-1.5 my-1.5 h-px bg-border", className)} {...props} />;
}
