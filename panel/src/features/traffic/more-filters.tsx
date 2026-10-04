"use client";

import { ICON_PATHS, PathIcon } from "@/components/rogatka";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

/**
 * "More filters ▾": group (single) and data class (several) in one menu.
 * Local to Traffic; could be promoted to a shared "sectioned filter menu" primitive.
 */
export function MoreFiltersButton({
  groups,
  group,
  onGroupChange,
  dataClasses,
  dataClass,
  onDataClassChange,
}: {
  groups: readonly string[];
  group: string | null;
  onGroupChange: (group: string | null) => void;
  dataClasses: readonly string[];
  dataClass: readonly string[];
  onDataClassChange: (classes: string[]) => void;
}) {
  const count = (group ? 1 : 0) + dataClass.length;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "inline-flex min-h-8 items-center gap-1.5 rounded-[6px] border px-2.5 text-[12.5px] text-text",
            count ? "border-accent-line bg-accent-soft" : "border-border bg-surface hover:border-border-strong",
          )}
        >
          More filters
          {count > 0 && <span className="font-mono text-muted">· {count}</span>}
          <PathIcon path={ICON_PATHS.chevronDown} size={11} strokeWidth={2.4} />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent aria-label="More filters">
        <DropdownMenuLabel>Group</DropdownMenuLabel>
        {groups.map((g) => (
          <DropdownMenuCheckboxItem
            key={g}
            checked={group === g}
            onSelect={(e) => e.preventDefault()}
            onCheckedChange={(on) => onGroupChange(on ? g : null)}
          >
            {g}
          </DropdownMenuCheckboxItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Data class</DropdownMenuLabel>
        {dataClasses.map((c) => (
          <DropdownMenuCheckboxItem
            key={c}
            checked={dataClass.includes(c)}
            onSelect={(e) => e.preventDefault()}
            onCheckedChange={(on) => onDataClassChange(on ? [...dataClass, c] : dataClass.filter((x) => x !== c))}
          >
            {c}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
