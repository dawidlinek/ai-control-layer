import * as React from "react";
import { cn } from "@/lib/utils";

/** Page title (20 px / 600), optional subtitle, actions on the right. */
export function PageHeader({
  title,
  subtitle,
  actions,
  className,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-x-3 gap-y-2", className)}>
      <div className="flex min-w-0 flex-col gap-0.5">
        <h1 className="m-0 text-[20px] font-semibold tracking-[-0.01em]">{title}</h1>
        {subtitle && <p className="m-0 text-[12.5px] text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** The one plain-language sentence at the top of every sidebar (generated from templates, never by an LLM). */
export function PlainSentence({ children, className }: { children: React.ReactNode; className?: string }) {
  return <p className={cn("m-0 text-[14px] leading-[1.5]", className)}>{children}</p>;
}

export interface Fact {
  label: string;
  value: React.ReactNode;
  /** Render the value in the mono font (ids, times, numbers). */
  mono?: boolean;
}

/** 4-8 key facts in a 2-column grid; values ellipsise. */
export function FactsGrid({ facts, className }: { facts: readonly Fact[]; className?: string }) {
  return (
    <dl className={cn("m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-[12.5px]", className)}>
      {facts.map((f) => (
        <div key={f.label} className="flex min-w-0 flex-col gap-px">
          <dt className="text-[11px] text-muted">{f.label}</dt>
          <dd className={cn("m-0 truncate", f.mono && "font-mono text-[12px]")}>{f.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Sidebar / card section: 11 px / 600 / uppercase / .08em label. */
export function SidebarSection({
  title,
  aside,
  children,
  className,
}: {
  title: React.ReactNode;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  const id = React.useId();
  return (
    <section aria-labelledby={id} className={cn("flex flex-col gap-2 border-b border-border p-3.5", className)}>
      <div className="flex items-baseline justify-between gap-2">
        <h3 id={id} className="m-0 text-[11px] font-semibold uppercase tracking-[.08em] text-muted">
          {title}
        </h3>
        {aside && <span className="text-[11.5px] text-muted">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

/** Overview-style card: surface, border, 8 px radius, 16 px padding, optional uppercase heading. */
export function Card({
  title,
  children,
  className,
  ...rest
}: { title?: React.ReactNode } & Omit<React.ComponentProps<"section">, "title">) {
  const id = React.useId();
  return (
    <section
      aria-labelledby={title ? id : undefined}
      className={cn("flex min-w-0 flex-col gap-3.5 rounded-[8px] border border-border bg-surface p-4", className)}
      {...rest}
    >
      {title && (
        <h2 id={id} className="m-0 text-[11px] font-semibold uppercase tracking-[.08em] text-muted">
          {title}
        </h2>
      )}
      {children}
    </section>
  );
}
