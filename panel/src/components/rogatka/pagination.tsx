"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ICON_PATHS, PathIcon } from "./icon";

/** Page numbers to show: first, last, current +-1, and 2-3 near the start; `null` marks a gap ("..."). */
export function pageWindow(page: number, pageCount: number): (number | null)[] {
  const want = new Set<number>([1, page - 1, page, page + 1, pageCount].filter((n) => n >= 1 && n <= pageCount));
  if (page <= 2) [2, 3].forEach((n) => n <= pageCount && want.add(n));
  const sorted = [...want].sort((a, b) => a - b);
  const out: (number | null)[] = [];
  sorted.forEach((n, i) => {
    if (i > 0 && n - sorted[i - 1] > 1) out.push(null);
    out.push(n);
  });
  return out;
}

const btn = "min-h-8 min-w-[34px] rounded-[6px] border border-border bg-surface px-2 text-[12.5px] disabled:opacity-50";

/**
 * "Rows per page 25 v" on the left, "< 1 2 3 ... N >" on the right.
 * Pass `pageCount` when the total is known; otherwise pass `hasNext` and only < page > is shown.
 */
export function Pagination({
  page,
  onPageChange,
  pageCount,
  hasNext,
  pageSize,
  onPageSizeChange,
  pageSizes = [25, 50, 100],
  className,
}: {
  /** 1-based. */
  page: number;
  onPageChange: (page: number) => void;
  pageCount?: number;
  hasNext?: boolean;
  pageSize: number;
  onPageSizeChange?: (size: number) => void;
  pageSizes?: readonly number[];
  className?: string;
}) {
  const last = pageCount ?? (hasNext ? page + 1 : page);
  const canNext = pageCount !== undefined ? page < pageCount : !!hasNext;
  return (
    <nav aria-label="Pagination" className={cn("flex flex-wrap items-center gap-2 text-[12.5px]", className)}>
      <span className="text-muted">Rows per page</span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label="Rows per page"
            className="inline-flex min-h-8 items-center gap-1.5 rounded-[6px] border border-border bg-surface px-2.5 text-[12.5px]"
          >
            {pageSize}
            <PathIcon path={ICON_PATHS.chevronDown} size={11} strokeWidth={2.4} />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuRadioGroup value={String(pageSize)} onValueChange={(v) => onPageSizeChange?.(Number(v))}>
            {pageSizes.map((s) => (
              <DropdownMenuRadioItem key={s} value={String(s)}>
                {s}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
      <div className="flex-1" />
      <button type="button" aria-label="Previous page" disabled={page <= 1} onClick={() => onPageChange(page - 1)} className={cn(btn, "text-muted")}>
        ‹
      </button>
      {pageCount !== undefined ? (
        pageWindow(page, pageCount).map((n, i) =>
          n === null ? (
            <span key={`gap-${i}`} className="px-0.5 text-muted" aria-hidden>
              …
            </span>
          ) : (
            <button
              key={n}
              type="button"
              aria-current={n === page ? "page" : undefined}
              onClick={() => onPageChange(n)}
              className={cn(btn, "font-mono", n === page ? "border-accent bg-accent-soft text-text" : "text-muted")}
            >
              {n}
            </button>
          ),
        )
      ) : (
        <span className="px-1 font-mono text-muted" aria-current="page">
          {page}
          {last > page ? "+" : ""}
        </span>
      )}
      <button type="button" aria-label="Next page" disabled={!canNext} onClick={() => onPageChange(page + 1)} className={btn}>
        ›
      </button>
    </nav>
  );
}
