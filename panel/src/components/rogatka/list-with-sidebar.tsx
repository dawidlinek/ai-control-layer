"use client";

import * as React from "react";
import { parseAsString, useQueryState } from "nuqs";
import { cn } from "@/lib/utils";
import { ICON_PATHS, PathIcon } from "./icon";

const SidebarContext = React.createContext<{ close: () => void } | null>(null);

/**
 * Selection in the URL: `?sel=<id>` (the "list + sidebar" pattern). `null` = sidebar closed.
 * Use the same hook in the table (`selectedId`, `onRowClick`) and in `ListWithSidebar` (`onClose`).
 */
export function useSelectedId() {
  return useQueryState("sel", parseAsString);
}

/**
 * Shared layout of every list screen except Overview: the list on the left (flex 999 1 560px) and a
 * right sidebar (flex 1 1 440px) next to it. When closed, the list uses the full width.
 * Esc closes the sidebar (when focus is not in a field).
 */
export function ListWithSidebar({
  list,
  sidebar,
  open,
  onClose,
  sidebarLabel,
  className,
}: {
  list: React.ReactNode;
  /** Sidebar content: SidebarHeader, PlainSentence, FactsGrid, SidebarSection..., SidebarActions. */
  sidebar: React.ReactNode;
  open: boolean;
  onClose: () => void;
  /** aria-label of the sidebar landmark ("Trace", "Incident"). */
  sidebarLabel: string;
  className?: string;
}) {
  React.useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      const el = e.target;
      if (el instanceof HTMLElement && (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || el.closest("[role=dialog],[role=menu]"))) return;
      onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <div className={cn("flex flex-wrap items-start gap-4", className)}>
      <section aria-label="List" className="flex min-w-0 flex-[999_1_560px] flex-col gap-3">
        {list}
      </section>
      {open && (
        <SidebarContext.Provider value={{ close: onClose }}>
          <aside
            aria-label={sidebarLabel}
            className="flex min-w-0 flex-[1_1_440px] flex-col overflow-hidden rounded-[8px] border border-border bg-surface"
          >
            {sidebar}
          </aside>
        </SidebarContext.Provider>
      )}
    </div>
  );
}

/** First row of a sidebar: small uppercase label, mono id, copy button, close x on the right. */
export function SidebarHeader({
  label,
  title,
  copyText,
  actions,
  onClose,
  className,
}: {
  label: string;
  /** Id or name; rendered mono. */
  title?: React.ReactNode;
  /** When set, a copy button copies this text. */
  copyText?: string;
  actions?: React.ReactNode;
  onClose?: () => void;
  className?: string;
}) {
  const ctx = React.useContext(SidebarContext);
  const close = onClose ?? ctx?.close;
  const [copied, setCopied] = React.useState(false);
  return (
    <div className={cn("flex items-center gap-2 border-b border-border px-3.5 py-2.5", className)}>
      <span className="text-[11px] font-bold uppercase tracking-[.1em] text-muted">{label}</span>
      {title && <span className="min-w-0 truncate font-mono text-[13px]">{title}</span>}
      {copyText && (
        <button
          type="button"
          aria-label={`Copy ${label.toLowerCase()} ID`}
          title={copied ? "Copied" : "Copy"}
          onClick={() => {
            void navigator.clipboard?.writeText(copyText);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          }}
          className="inline-flex rounded-[4px] border-0 bg-transparent p-1 text-muted hover:text-text"
        >
          <PathIcon path={copied ? ICON_PATHS.check : ICON_PATHS.copy} size={13} />
        </button>
      )}
      <div className="flex-1" />
      {actions}
      {close && (
        <button
          type="button"
          aria-label={`Close ${label.toLowerCase()}`}
          onClick={close}
          className="inline-flex size-[30px] items-center justify-center rounded-[6px] border-0 bg-transparent text-muted hover:bg-raised hover:text-text"
        >
          <PathIcon path={ICON_PATHS.close} size={15} />
        </button>
      )}
    </div>
  );
}

/** Unlabelled sidebar block (chips + sentence + facts): 14 px padding, 12 px gap, bottom border. */
export function SidebarBlock({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-col gap-3 border-b border-border p-3.5", className)}>{children}</div>;
}

/** Last row of a sidebar: action buttons. */
export function SidebarActions({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap gap-2 px-3.5 py-3", className)}>{children}</div>;
}
