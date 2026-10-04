"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { ALL_NAV_ITEMS } from "./nav-config";

function isTyping(el: EventTarget | null): boolean {
  return (
    el instanceof HTMLElement &&
    (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || !!el.closest("[role=dialog],[role=menu]"))
  );
}

/**
 * Global single-key shortcuts (ignored while typing or inside dialogs / menus):
 * `?` shortcut help, `g` then a letter = go to a screen, `/` = focus the page's search field.
 * `j` / `k` / `Enter` (tables) and `Esc` (close sidebar) are handled by DataTable and ListWithSidebar.
 */
export function useGlobalShortcuts(onHelp: () => void) {
  const router = useRouter();
  const helpRef = React.useRef(onHelp);
  React.useEffect(() => {
    helpRef.current = onHelp;
  });
  React.useEffect(() => {
    let chord = false;
    let timer: number | undefined;
    function onKey(e: KeyboardEvent) {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
      if (chord) {
        chord = false;
        window.clearTimeout(timer);
        const item = ALL_NAV_ITEMS.find((i) => i.shortcut === e.key);
        if (item) {
          e.preventDefault();
          router.push(item.href);
        }
        return;
      }
      if (e.key === "?") {
        e.preventDefault();
        helpRef.current();
      } else if (e.key === "g") {
        chord = true;
        timer = window.setTimeout(() => (chord = false), 1200);
      } else if (e.key === "/") {
        const field = document.querySelector<HTMLInputElement>("main input[type=search]");
        if (field) {
          e.preventDefault();
          field.focus();
        }
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      window.clearTimeout(timer);
    };
  }, [router]);
}

const OTHER: Array<[string[], string]> = [
  [["?"], "Show this help"],
  [["/"], "Focus the search field of the page"],
  [["j", "k"], "Move down / up in a table"],
  [["Enter"], "Open the highlighted row"],
  [["Esc"], "Close the sidebar"],
];

function Keys({ keys }: { keys: string[] }) {
  return (
    <span className="flex items-center gap-1">
      {keys.map((k, i) => (
        <React.Fragment key={`${k}-${i}`}>
          {i > 0 && <span className="text-muted">then</span>}
          <kbd className="min-w-6 rounded-[4px] border border-border-strong bg-raised px-1.5 py-px text-center font-mono text-[11.5px]">{k}</kbd>
        </React.Fragment>
      ))}
    </span>
  );
}

export function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle>Keyboard shortcuts</DialogTitle>
        <DialogDescription>Single keys work when the cursor is not in a text field.</DialogDescription>
        <ul className="m-0 flex list-none flex-col p-0">
          {OTHER.map(([keys, label]) => (
            <li key={label} className="flex items-center justify-between gap-3 border-b border-border py-1.5 text-[12.5px]">
              <span>{label}</span>
              <Keys keys={keys} />
            </li>
          ))}
        </ul>
        <h3 className="m-0 mt-1 text-[11px] font-semibold uppercase tracking-[.08em] text-muted">Go to</h3>
        <ul className="m-0 grid list-none grid-cols-2 gap-x-6 p-0">
          {ALL_NAV_ITEMS.map((item) => (
            <li key={item.href} className="flex items-center justify-between gap-3 border-b border-border py-1.5 text-[12.5px]">
              <span>{item.label}</span>
              <Keys keys={["g", item.shortcut]} />
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}
