"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ICON_PATHS, PathIcon } from "./icon";

/** Row under the page title: segmented tabs, filter buttons, search, optional switch on the right. */
export function FilterRow({ children, className, ...rest }: React.ComponentProps<"div">) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)} {...rest}>
      {children}
    </div>
  );
}

/** Pushes the following filter-row items to the right edge. */
export function FilterSpacer() {
  return <div className="flex-1" aria-hidden />;
}

export interface TabItem<V extends string = string> {
  value: V;
  label: React.ReactNode;
  /** Shown after the label in mono muted ("Open 7"). */
  count?: number | string;
}

const segBase = "inline-flex overflow-hidden rounded-[6px] border border-border";
const segBtn =
  "min-h-8 border-0 border-r border-border px-3 text-[12.5px] last:border-r-0 transition-colors";

/** Tabs with counts ("Open 7 | Resolved 2 | All 9"). Page-level tabs too (Rules | YAML | History). */
export function SegmentedTabs<V extends string = string>({
  tabs,
  value,
  onChange,
  ariaLabel = "View",
  className,
}: {
  tabs: readonly TabItem<V>[];
  value: V;
  onChange: (value: V) => void;
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <div role="tablist" aria-label={ariaLabel} className={cn(segBase, className)}>
      {tabs.map((t) => {
        const on = t.value === value;
        return (
          <button
            key={t.value}
            role="tab"
            type="button"
            aria-selected={on}
            data-state={on ? "active" : "inactive"}
            onClick={() => onChange(t.value)}
            className={cn(segBtn, on ? "bg-accent-soft font-medium text-text" : "bg-transparent text-muted hover:text-text")}
          >
            {t.label}
            {t.count !== undefined && <span className="ml-1.5 font-mono text-muted">{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export interface SegmentedOption<V extends string = string> {
  value: V;
  label: React.ReactNode;
  /** Disable just this option. */
  disabled?: boolean;
}

/**
 * Small option switch (theme Dark | Light, range 15m | 1h | 24h | 7d, strictness). Buttons with `aria-pressed`.
 * `disabled` disables the whole control, `option.disabled` a single button; disabled buttons never call `onChange`.
 */
export function Segmented<V extends string = string>({
  options,
  value,
  onChange,
  ariaLabel,
  size = "md",
  disabled = false,
  className,
}: {
  options: readonly SegmentedOption<V>[];
  value: V;
  onChange: (value: V) => void;
  ariaLabel: string;
  size?: "sm" | "md";
  disabled?: boolean;
  className?: string;
}) {
  return (
    <div role="group" aria-label={ariaLabel} aria-disabled={disabled || undefined} className={cn(segBase, className)}>
      {options.map((o) => {
        const on = o.value === value;
        const off = disabled || !!o.disabled;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            disabled={off}
            aria-disabled={off || undefined}
            onClick={() => {
              if (!off) onChange(o.value);
            }}
            className={cn(
              "border-0 border-r border-border text-[12px] last:border-r-0",
              size === "sm" ? "px-2.5 py-1" : "min-h-8 px-3",
              on ? "bg-accent-soft text-text" : "bg-transparent text-muted hover:text-text",
              off && "cursor-not-allowed opacity-50 hover:text-muted",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export interface FilterOption {
  value: string;
  label: React.ReactNode;
}

/**
 * Button with a down caret that opens a checkable menu ("Decision ▾"). Multi-select by default
 * (stays open while ticking); `multiple={false}` makes it a single choice that closes on pick.
 * When something is selected the button is highlighted and shows the count (or the single label).
 */
export function FilterMenuButton({
  label,
  options,
  selected,
  onChange,
  multiple = true,
  icon,
  className,
}: {
  label: string;
  options: readonly FilterOption[];
  selected: readonly string[];
  onChange: (selected: string[]) => void;
  multiple?: boolean;
  /** Optional leading icon path (e.g. ICON_PATHS.calendar for the time range). */
  icon?: string;
  className?: string;
}) {
  const active = selected.length > 0;
  const single = !multiple && active ? options.find((o) => o.value === selected[0])?.label : null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "inline-flex min-h-8 items-center gap-1.5 rounded-[6px] border px-2.5 text-[12.5px] text-text",
            active ? "border-accent-line bg-accent-soft" : "border-border bg-surface hover:border-border-strong",
            className,
          )}
        >
          {icon && <PathIcon path={icon} size={13} />}
          {single ?? label}
          {multiple && active && <span className="font-mono text-muted">· {selected.length}</span>}
          <PathIcon path={ICON_PATHS.chevronDown} size={11} strokeWidth={2.4} />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent aria-label={label}>
        {options.map((o) => {
          const on = selected.includes(o.value);
          return (
            <DropdownMenuCheckboxItem
              key={o.value}
              checked={on}
              onSelect={(e) => {
                if (multiple) e.preventDefault();
              }}
              onCheckedChange={(next) => {
                if (multiple) onChange(next ? [...selected, o.value] : selected.filter((v) => v !== o.value));
                else onChange(next ? [o.value] : []);
              }}
            >
              {o.label}
            </DropdownMenuCheckboxItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Search field on the inset surface with a leading magnifier. Controlled; pair with nuqs `q`. */
export function SearchInput({
  value,
  onChange,
  placeholder = "Search",
  ariaLabel,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <label
      className={cn(
        "flex min-h-8 min-w-[150px] flex-[0_1_240px] items-center gap-1.5 rounded-[6px] border border-border bg-inset px-2.5 text-muted",
        className,
      )}
    >
      <PathIcon path={ICON_PATHS.search} size={13} />
      <input
        type="search"
        aria-label={ariaLabel ?? placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="min-w-0 flex-1 border-0 bg-transparent text-[12.5px] text-text outline-none placeholder:text-muted focus-visible:outline-none [&::-webkit-search-cancel-button]:hidden"
      />
    </label>
  );
}

/** Switch with a visible label ("Hide allowed", "Assigned to me"). */
export function LabeledSwitch({
  label,
  checked,
  onCheckedChange,
  disabled,
  className,
}: {
  label: React.ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  const id = React.useId();
  return (
    <div className={cn("inline-flex min-h-8 items-center gap-2 px-1 text-[12.5px]", className)}>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled} />
      <label htmlFor={id} className="cursor-pointer select-none">
        {label}
      </label>
    </div>
  );
}
