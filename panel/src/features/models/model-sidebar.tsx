"use client";

import Link from "next/link";
import { FactsGrid, PlainSentence, SidebarActions, SidebarBlock, SidebarHeader, SidebarSection } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { ArtifactScanResult, ModelInfo } from "@/lib/api/types";
import { fileResult, shortHash } from "@/features/threats/artifact-copy";
import {
  aboutText,
  autoReasons,
  autoShare,
  connectorName,
  dataClassesText,
  modelFileName,
  otherTags,
  priceText,
  whoCanUse,
} from "./details";

function modelFileLine(m: ModelInfo, artifacts: readonly ArtifactScanResult[] | undefined): string {
  if (m.tier === "cloud") return `Hosted by ${connectorName(m.connector)}: no model file to scan.`;
  const name = modelFileName(m);
  const scan = name ? artifacts?.find((a) => a.filename === name) : undefined;
  if (scan) {
    const r = fileResult(scan);
    return `${scan.filename} · ${r === "passed" ? `${scan.format_detected} scan passed` : `scan ${r}`} · sha256 ${shortHash(scan.sha256)}`;
  }
  if (name) return `${name} · ${m.artifact_status === "scanned_ok" ? "scan passed" : m.artifact_status === "scanned_bad" ? "scan blocked" : "not scanned yet"}`;
  if (m.artifact_status === "scanned_ok") return "The model file was scanned before registration and passed.";
  if (m.artifact_status === "scanned_bad") return "The model file was blocked by the scan.";
  return "No model file recorded.";
}

export function ModelSidebar({
  model: m,
  off,
  artifacts,
}: {
  model: ModelInfo;
  off: boolean;
  artifacts: readonly ArtifactScanResult[] | undefined;
}) {
  const who = whoCanUse(m);
  const share = autoShare(m);
  const reasons = autoReasons(m);
  return (
    <>
      <SidebarHeader label="Model" title={m.id} copyText={m.id} />
      <SidebarBlock>
        <PlainSentence>
          {aboutText(m)}
          {off && " It is switched off right now."}
        </PlainSentence>
        <FactsGrid
          facts={[
            { label: "Connector", value: `${m.connector} (${m.tier})` },
            { label: "Alias", value: m.aliases.length ? m.aliases.join(", ") : "—", mono: true },
            { label: "Price", value: priceText(m) },
            { label: "Data it may get", value: dataClassesText(m.data_classes) },
            { label: "Tags", value: otherTags(m) },
            { label: "Limit", value: m.tags.limit ?? "—" },
          ]}
        />
      </SidebarBlock>
      <SidebarSection title="Who can use it">
        {who.length ? (
          <div className="flex flex-wrap gap-1.5">
            {who.map((w) => {
              const body = (
                <>
                  {w.label} <span className="text-muted">{w.how}</span>
                </>
              );
              const cls = cn(
                "rounded-full border px-2.5 py-0.5 text-[12px] text-text no-underline",
                w.grant ? "border-accent-line" : "border-border",
              );
              return w.href ? (
                <Link key={w.label} href={w.href} className={cn(cls, "hover:border-accent")}>
                  {body}
                </Link>
              ) : (
                <span key={w.label} className={cls}>
                  {body}
                </span>
              );
            })}
          </div>
        ) : (
          <span className="text-[12.5px] text-muted">Set by group rules and grants (see Users & groups).</span>
        )}
      </SidebarSection>
      <SidebarSection title="How auto picks it">
        {share ? (
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-[22px] font-semibold">{share}</span>
            <span className="text-[12.5px] text-muted">of auto requests today</span>
          </div>
        ) : (
          <span className="text-[12.5px] text-muted">
            {m.requests_day ? `${m.requests_day} requests today.` : "No requests today."} No breakdown by reason from the gateway.
          </span>
        )}
        {reasons.length > 0 && (
          <ul aria-label="Reasons" className="m-0 flex list-none flex-col gap-1 p-0">
            {reasons.map((r) => (
              <li key={r.label} className="grid grid-cols-[minmax(0,1fr)_56px] gap-2 text-[12.5px]">
                <span>{r.label}</span>
                <span className="text-right font-mono text-muted">{r.count}</span>
              </li>
            ))}
          </ul>
        )}
      </SidebarSection>
      <SidebarSection title="Model file" className="border-b-0">
        <span className="text-[12.5px]">{modelFileLine(m, artifacts)}</span>
      </SidebarSection>
      <SidebarActions>
        <Button asChild>
          <Link href="/policies?tab=yaml">Edit in Policies</Link>
        </Button>
        <Button
          variant="ghost"
          className="border-border text-dec-block"
          disabled
          title="Not available in the admin API yet: switch the connector off, or remove the model in models.yaml"
        >
          Turn off model
        </Button>
      </SidebarActions>
    </>
  );
}
