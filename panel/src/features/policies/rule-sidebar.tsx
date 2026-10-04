"use client";

import Link from "next/link";
import { DecisionBadge, FactsGrid, ICON_PATHS, PathIcon, PlainSentence, SidebarBlock, SidebarHeader, SidebarSection } from "@/components/rogatka";
import type { PolicyFileContent } from "@/lib/api/types";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import { RuleSetting } from "./rule-setting";
import type { PolicyRule } from "./rules";

const MODE_CLASS: Record<PolicyRule["mode"], string> = {
  enforce: "text-muted",
  monitor: "text-dec-downgrade",
  always: "text-muted",
  off: "text-muted",
};

export function ModeLabel({ mode }: { mode: PolicyRule["mode"] }) {
  return <span className={MODE_CLASS[mode]}>{mode}</span>;
}

export function hitsText(hits: Record<string, number> | undefined, id: string): string {
  const n = hits?.[id];
  return n === undefined ? "—" : formatNumber(n);
}

export function RuleSidebar({
  rule,
  hits,
  controlsFile,
  onOpenYaml,
}: {
  rule: PolicyRule;
  hits: Record<string, number> | undefined;
  controlsFile: PolicyFileContent | undefined;
  /** Switch to the YAML tab on the rule's file; omitted on the YAML tab itself. */
  onOpenYaml?: () => void;
}) {
  return (
    <>
      <SidebarHeader
        label="Rule"
        title={
          <>
            <span className="font-semibold">{rule.id}</span>
            <span className="ml-2 font-sans text-[12.5px] text-muted">{rule.typeLabel}</span>
          </>
        }
        copyText={rule.id}
      />
      <SidebarBlock>
        <PlainSentence>{rule.explain}</PlainSentence>
        <FactsGrid
          facts={[
            { label: "Action", value: <DecisionBadge decision={rule.action} /> },
            { label: "Mode", value: <ModeLabel mode={rule.mode} /> },
            { label: "Hits in 24 h", value: hitsText(hits, rule.id), mono: true },
            { label: "Where", value: `${rule.file}${rule.line ? ` · L${rule.line}` : ""}`, mono: true },
            ...(rule.stages.length ? [{ label: "Checks", value: rule.stages.join(", ") }] : []),
            ...(rule.costTier ? [{ label: "Cost tier", value: `${rule.costTier}${rule.timeoutMs ? ` · ${rule.timeoutMs} ms` : ""}`, mono: true }] : []),
          ]}
        />
        {rule.locked && (
          <div className="flex items-start gap-2 rounded-[6px] border border-border bg-inset px-2.5 py-2 text-[12px] text-muted">
            <PathIcon path={ICON_PATHS.lock} size={13} className="mt-0.5 shrink-0" />
            <span>
              Org lock{rule.lockId && rule.lockId !== rule.id ? ` ${rule.lockId}` : ""} — it can’t be changed or turned off here. Changes go
              through the file with a review.
            </span>
          </div>
        )}
      </SidebarBlock>

      {rule.setting && controlsFile && (
        <SidebarSection title="Setting">
          <RuleSetting key={rule.id} rule={rule} file={controlsFile} />
        </SidebarSection>
      )}

      <SidebarSection title="In the file" className="border-b-0">
        {rule.snippet.length > 0 ? (
          <pre
            aria-label={`${rule.id} in ${rule.file}`}
            className="m-0 overflow-x-auto rounded-[6px] border border-border bg-inset px-2.5 py-2 font-mono text-[12px] leading-[1.6]"
          >
            {rule.snippet.map((l) => (
              <div key={l.n} className={cn("whitespace-pre", l.n === rule.line && "text-text")}>
                <span className="inline-block w-9 select-none pr-2 text-right text-muted">L{l.n}</span>
                {l.text}
              </div>
            ))}
          </pre>
        ) : (
          <p className="m-0 text-[12.5px] text-muted">Not found in {rule.file}.</p>
        )}
        <div className="flex flex-wrap gap-3.5 text-[12.5px]">
          {onOpenYaml && (
            <button type="button" onClick={onOpenYaml} className="border-0 bg-transparent p-0 text-accent underline">
              Open in YAML
            </button>
          )}
          <Link href={`/traffic?rule=${encodeURIComponent(rule.id)}`} className="text-accent">
            See its hits in Traffic
          </Link>
        </div>
      </SidebarSection>
    </>
  );
}
