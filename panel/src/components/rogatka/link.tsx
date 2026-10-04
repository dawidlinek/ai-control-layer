import * as React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";

/** In-text and cross-screen links are ink with an underline (brand red is for marks only, STYLEGUIDE section 2). */
export const linkClass =
  "text-text underline decoration-border-strong decoration-1 underline-offset-[3px] hover:decoration-text";

/** `next/link` styled as an ink text link; pass `className` for size (`text-[13px]`) or layout. */
export function TextLink({ className, ...props }: React.ComponentProps<typeof Link>) {
  return <Link className={cn(linkClass, className)} {...props} />;
}
