"use client";

import * as React from "react";
import { Dialog as Primitive } from "radix-ui";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export const Dialog = Primitive.Root;
export const DialogTrigger = Primitive.Trigger;
export const DialogClose = Primitive.Close;

export function DialogContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof Primitive.Content>) {
  return (
    <Primitive.Portal>
      <Primitive.Overlay className="rg-fade fixed inset-0 z-50 bg-black/55" />
      <Primitive.Content
        data-slot="dialog-content"
        className={cn(
          "rg-pop fixed left-1/2 top-1/2 z-50 flex max-h-[85vh] w-[min(520px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-[10px] border border-border-strong bg-surface p-5 text-text shadow-[var(--shadow-pop)]",
          className,
        )}
        {...props}
      >
        {children}
        <Primitive.Close
          aria-label="Close"
          className="absolute right-3 top-3 inline-flex size-8 items-center justify-center rounded-[6px] text-muted hover:bg-raised"
        >
          <X className="size-4" aria-hidden />
        </Primitive.Close>
      </Primitive.Content>
    </Primitive.Portal>
  );
}

export function DialogTitle({ className, ...props }: React.ComponentProps<typeof Primitive.Title>) {
  return <Primitive.Title className={cn("m-0 text-[15px] font-semibold", className)} {...props} />;
}

export function DialogDescription({ className, ...props }: React.ComponentProps<typeof Primitive.Description>) {
  return <Primitive.Description className={cn("m-0 text-[12.5px] text-muted", className)} {...props} />;
}
