"use client";

import * as React from "react";
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef, type RowData } from "@tanstack/react-table";
import { cn } from "@/lib/utils";
import { EmptyState, ErrorState, LoadingRows } from "./status";

declare module "@tanstack/react-table" {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Extra classes for body cells of this column (e.g. `font-mono text-[12px]`, `w-20`). */
    className?: string;
    /** Extra classes for the header cell. */
    headerClassName?: string;
  }
}

function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  return el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || !!el.closest("[role=dialog],[role=menu]");
}

export interface DataTableProps<T> {
  data: readonly T[];
  columns: ColumnDef<T, any>[]; // eslint-disable-line @typescript-eslint/no-explicit-any
  /** Stable id of a row; used for selection and keys. */
  getRowId: (row: T) => string;
  /** Id of the selected row (drives the accent-soft background and the 3 px accent bar). */
  selectedId?: string | null;
  /** Row click / Enter. Clicks on links and buttons inside a row do not trigger it. */
  onRowClick?: (row: T) => void;
  ariaLabel: string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  emptyTitle?: React.ReactNode;
  emptyMessage?: React.ReactNode;
  /** j / k move through rows, Enter opens (single-key shortcuts, ignored while typing). */
  keyboardNav?: boolean;
  /** Minimum table width in px before the box scrolls horizontally. Default 760. */
  minWidth?: number;
  className?: string;
}

/**
 * TanStack Table wrapper in the Rogatka look: header 10.5 px uppercase muted, compact 8 px rows,
 * whole row clickable, selected row = accent-soft + 3 px accent bar, horizontal scroll inside the box.
 */
export function DataTable<T>({
  data,
  columns,
  getRowId,
  selectedId,
  onRowClick,
  ariaLabel,
  loading,
  error,
  onRetry,
  emptyTitle,
  emptyMessage,
  keyboardNav,
  minWidth = 760,
  className,
}: DataTableProps<T>) {
  const table = useReactTable({
    data: data as T[],
    columns,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
  });
  const rows = table.getRowModel().rows;
  const bodyRef = React.useRef<HTMLTableSectionElement>(null);
  const [cursor, setCursor] = React.useState<string | null>(null);

  // j / k / Enter
  React.useEffect(() => {
    if (!keyboardNav) return;
    function onKey(e: KeyboardEvent) {
      if (e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target) || rows.length === 0) return;
      const ids = rows.map((r) => r.id);
      const current = cursor ?? selectedId ?? null;
      const idx = current ? ids.indexOf(current) : -1;
      if (e.key === "j" || e.key === "k") {
        e.preventDefault();
        const next = Math.min(ids.length - 1, Math.max(0, idx + (e.key === "j" ? 1 : -1)));
        const nextId = ids[next];
        setCursor(nextId);
        // When a row is already open, the sidebar follows the cursor.
        if (selectedId) onRowClick?.(rows[next].original);
        bodyRef.current?.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(nextId)}"]`)?.scrollIntoView?.({ block: "nearest" });
      } else if (e.key === "Enter" && idx >= 0 && !(e.target instanceof HTMLElement && e.target.closest("a,button"))) {
        e.preventDefault();
        onRowClick?.(rows[idx].original);
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [keyboardNav, rows, cursor, selectedId, onRowClick]);

  return (
    <div className={cn("rg-scroll relative overflow-x-auto rounded-[8px] border border-border bg-surface", className)}>
      <table aria-label={ariaLabel} className="w-full border-separate border-spacing-0 text-[12.5px]" style={{ minWidth }}>
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => (
                <th
                  key={h.id}
                  scope="col"
                  className={cn(
                    "border-b border-border px-2.5 py-[9px] text-left text-[10.5px] font-semibold uppercase tracking-[.05em] text-muted first:pl-3.5 last:pr-3.5",
                    h.column.columnDef.meta?.headerClassName,
                  )}
                >
                  {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody ref={bodyRef}>
          {!loading &&
            !error &&
            rows.map((row) => {
              const selected = selectedId != null && row.id === selectedId;
              const focused = cursor === row.id && !selected;
              return (
                <tr
                  key={row.id}
                  data-row-id={row.id}
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={onRowClick ? selected : undefined}
                  data-selected={selected || undefined}
                  onClick={(e) => {
                    if (!onRowClick) return;
                    if ((e.target as HTMLElement).closest("a,button,input,label,[role=menuitem]")) return;
                    setCursor(row.id);
                    onRowClick(row.original);
                  }}
                  onKeyDown={(e) => {
                    if (onRowClick && e.key === "Enter" && e.target === e.currentTarget) {
                      e.preventDefault();
                      onRowClick(row.original);
                    }
                  }}
                  className={cn(
                    "group",
                    onRowClick && "cursor-pointer",
                    selected ? "bg-accent-soft" : "hover:bg-raised",
                    focused && "outline-1 -outline-offset-1 outline-accent-line",
                  )}
                >
                  {row.getVisibleCells().map((cell, i) => (
                    <td
                      key={cell.id}
                      className={cn(
                        "border-b border-border px-2.5 py-2 align-middle first:pl-3.5 last:pr-3.5",
                        i === 0 && selected && "shadow-[inset_3px_0_0_var(--accent)]",
                        cell.column.columnDef.meta?.className,
                      )}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })}
        </tbody>
      </table>
      {loading && <LoadingRows />}
      {!loading && !!error && <ErrorState error={error} onRetry={onRetry} />}
      {!loading && !error && rows.length === 0 && <EmptyState title={emptyTitle}>{emptyMessage}</EmptyState>}
    </div>
  );
}

/** Ellipsising cell content: `<Truncate className="font-mono">...</Truncate>` inside a column with a fixed width. */
export function Truncate({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("block max-w-full truncate", className)}>{children}</span>;
}
