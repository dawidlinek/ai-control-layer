"use client";

import Link from "next/link";
import {
  DecisionBadge,
  FactsGrid,
  ICON_PATHS,
  PathIcon,
  PlainSentence,
  SidebarBlock,
  SidebarHeader,
  SidebarSection,
  SeverityChip,
  TimeCell,
  linkClass,
} from "@/components/rogatka";
import { formatNumber, formatWhen } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ArtifactScanResult, EventSummary, FeedSignature } from "@/lib/api/types";
import { fileAbout, fileResult, shortHash, technicalDetail, type FileResult } from "./artifact-copy";
import { useRuleHits } from "./api";
import { expiresLabel, looksAt, tagsOf } from "./signatures";

function hitText(e: EventSummary): string {
  const who = e.username ?? e.agent_id ?? e.subject ?? "someone";
  const what = e.tool_preview ?? e.tool ?? e.model ?? e.point ?? e.event_type;
  return `${who} · ${what}`;
}

export function SignatureSidebar({ sig }: { sig: FeedSignature }) {
  const recent = useRuleHits(sig.hits_24h === 0 ? null : sig.id);
  const hits = sig.hits_24h === 0 ? [] : recent.data;
  return (
    <>
      <SidebarHeader label="Signature" title={sig.id} copyText={sig.id} />
      <SidebarBlock>
        <PlainSentence>{sig.description || sig.title}</PlainSentence>
        <pre aria-label="Pattern" className="m-0 overflow-x-auto rounded-[6px] border border-border bg-inset px-2.5 py-2 font-mono text-[12px]">
          {sig.pattern}
        </pre>
        <FactsGrid
          facts={[
            { label: "Looks at", value: looksAt(sig.target) },
            { label: "Action", value: <DecisionBadge decision={sig.action} /> },
            { label: "Severity", value: <SeverityChip severity={sig.severity} /> },
            { label: "Hits 24 h", value: sig.last_hit_at ? `${formatNumber(sig.hits_24h ?? 0)} · last ${formatWhen(sig.last_hit_at)}` : formatNumber(sig.hits_24h ?? 0), mono: true },
            { label: "Tags", value: tagsOf(sig), mono: true },
            { label: "Source", value: sig.reference ? `${sig.source || "—"} · ${sig.reference}` : sig.source || "—" },
            { label: "From", value: sig.origin === "feed" ? "signature feed" : "offline baseline (policy)" },
            { label: "Expires", value: expiresLabel(sig) },
          ]}
        />
      </SidebarBlock>
      <SidebarSection
        title="Recent hits"
        aside={
          <Link href={`/traffic?rule=${encodeURIComponent(sig.id)}`} className={linkClass}>
            All in Traffic →
          </Link>
        }
        className="border-b-0"
      >
        {hits === undefined ? (
          <span className="text-[13px] text-muted">Loading…</span>
        ) : hits.length === 0 ? (
          <span className="text-[13px] text-muted">No hits in the last 24 hours.</span>
        ) : (
          <ul aria-label="Recent hits" className="m-0 flex list-none flex-col gap-1.5 p-0">
            {hits.slice(0, 5).map((e) => (
              <li key={e.event_id}>
                <Link
                  href={`/traffic?sel=${encodeURIComponent(e.trace_id ?? e.event_id)}`}
                  className="grid grid-cols-[66px_minmax(0,1fr)_14px] gap-2 rounded-[6px] border border-border px-2 py-1.5 text-[13px] text-text no-underline hover:border-border-strong"
                >
                  <TimeCell iso={e.timestamp} className="text-muted" />
                  <span className="truncate">{hitText(e)}</span>
                  <span aria-hidden className="text-muted">
                    ›
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </SidebarSection>
    </>
  );
}

const RESULT_CLASS: Record<FileResult, string> = {
  passed: "text-dec-allow",
  blocked: "text-dec-block",
  suspicious: "text-dec-require-approval",
};

export function ResultLabel({ result, className }: { result: FileResult; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5", RESULT_CLASS[result], className)}>
      <PathIcon path={result === "passed" ? ICON_PATHS.check : result === "blocked" ? ICON_PATHS.error : ICON_PATHS.warning} size={12} strokeWidth={2.4} />
      {result}
    </span>
  );
}

function sizeText(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${formatNumber(Math.round(bytes / 1024 ** 2))} MB`;
  return `${formatNumber(Math.round(bytes / 1024))} kB`;
}

export function FileSidebar({ file: a }: { file: ArtifactScanResult }) {
  return (
    <>
      <SidebarHeader label="Model file" title={a.filename} copyText={a.sha256} />
      <SidebarBlock>
        <ResultLabel result={fileResult(a)} className="text-[13px] font-semibold" />
        <PlainSentence>{fileAbout(a)}</PlainSentence>
        <pre aria-label="Technical detail" className="m-0 whitespace-pre-wrap rounded-[6px] border border-border bg-inset px-2.5 py-2 font-mono text-[12px]">
          {technicalDetail(a)}
        </pre>
        <dl className="m-0 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 text-[13px]">
          <dt className="text-muted">sha256</dt>
          <dd className="m-0 font-mono" title={a.sha256}>
            {shortHash(a.sha256)}
          </dd>
          <dt className="text-muted">Format</dt>
          <dd className="m-0">{a.format_detected}</dd>
          <dt className="text-muted">Size</dt>
          <dd className="m-0 font-mono">{sizeText(a.size)}</dd>
          <dt className="text-muted">Scanned</dt>
          <dd className="m-0">{formatWhen(a.scanned_at)}</dd>
        </dl>
      </SidebarBlock>
      {a.findings.length > 0 && (
        <SidebarSection title="Findings" className="border-b-0">
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
            {a.findings.map((f, i) => (
              <li key={`${f.rule_id}-${i}`} className="flex flex-wrap items-center gap-2 text-[13px]">
                <SeverityChip severity={f.severity === "info" ? "low" : f.severity} />
                <span className="font-mono text-[12px]">{f.rule_id}</span>
              </li>
            ))}
          </ul>
        </SidebarSection>
      )}
    </>
  );
}
