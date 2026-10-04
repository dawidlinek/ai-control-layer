import * as React from "react";
import { cn } from "@/lib/utils";
import { ICON_PATHS, PathIcon } from "./icon";
import { Button } from "@/components/ui/button";

export type StatusVariant = "success" | "info" | "warning" | "error";

const STATUS: Record<StatusVariant, { v: string; icon: string }> = {
  success: { v: "var(--dec-allow)", icon: ICON_PATHS.check },
  info: { v: "var(--dec-route-local)", icon: ICON_PATHS.info },
  warning: { v: "var(--dec-downgrade)", icon: ICON_PATHS.warning },
  error: { v: "var(--dec-block)", icon: ICON_PATHS.error },
};

/**
 * Inline result of an action ("v9 is live", "Saved as policy v9"), shown in the sidebar where the action was.
 * success = green, info = blue, warning = amber, error = red. `error` is announced assertively.
 */
export function StatusBox({
  variant = "info",
  title,
  children,
  className,
}: {
  variant?: StatusVariant;
  title?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}) {
  const s = STATUS[variant];
  return (
    <div
      role={variant === "error" ? "alert" : "status"}
      data-variant={variant}
      className={cn("tint flex items-start gap-2.5 rounded-[6px] px-3 py-2.5 text-[13.5px]", className)}
      style={{ "--c": s.v } as React.CSSProperties}
    >
      <PathIcon path={s.icon} size={15} className="mt-px shrink-0" />
      <div className="flex min-w-0 flex-col gap-0.5 text-text">
        {title && <b className="font-semibold">{title}</b>}
        {children && <div className="text-text">{children}</div>}
      </div>
    </div>
  );
}

export function EmptyState({
  title = "Nothing here",
  children,
  action,
  className,
}: {
  title?: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center gap-1.5 px-4 py-8 text-center text-muted", className)}>
      <b className="font-semibold text-text">{title}</b>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Could not load this",
  error,
  onRetry,
  className,
}: {
  title?: React.ReactNode;
  error?: unknown;
  onRetry?: () => void;
  className?: string;
}) {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
  return (
    <div role="alert" className={cn("flex flex-col items-center gap-2 px-4 py-8 text-center", className)}>
      <b className="font-semibold text-dec-block">{title}</b>
      {message && <span className="text-muted">{message}</span>}
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

/** Skeleton rows for tables / lists while data loads. */
export function LoadingRows({ rows = 6, className }: { rows?: number; className?: string }) {
  return (
    <div role="status" aria-label="Loading" className={cn("flex flex-col", className)}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3 border-b border-border px-3.5 py-3">
          <span className="h-3 w-16 animate-pulse rounded-[3px] bg-raised" />
          <span className="h-3 w-28 animate-pulse rounded-[3px] bg-raised" />
          <span className="h-3 flex-1 animate-pulse rounded-[3px] bg-raised" />
          <span className="h-3 w-12 animate-pulse rounded-[3px] bg-raised" />
        </div>
      ))}
    </div>
  );
}
