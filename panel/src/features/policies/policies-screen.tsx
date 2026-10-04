"use client";

import * as React from "react";
import { parseAsString, parseAsStringLiteral, useQueryState, useQueryStates } from "nuqs";
import { FilterRow, FilterSpacer, SearchInput, SegmentedTabs, StatusBox } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { useUser } from "@/lib/auth/user-context";
import type { PolicyStatus, PolicyVersion } from "@/lib/api/types";
import { usePolicyStatus, usePolicyVersions } from "./api";
import { liveSentence, versionLabel } from "./helpers";
import { HistoryTab } from "./history-tab";
import { RulesTab } from "./rules-tab";
import { YamlTab } from "./yaml-tab";

const TABS = ["rules", "yaml", "history"] as const;

function LiveHeader({ status, versions }: { status: PolicyStatus | undefined; versions: PolicyVersion[] | undefined }) {
  const me = useUser().username;
  return (
    <div className="flex flex-wrap items-baseline gap-x-3.5 gap-y-1.5">
      <h1 className="m-0 text-[20px] font-semibold tracking-[-0.01em]">Policies</h1>
      {status && (
        <span className="text-[12.5px] text-muted" data-testid="policy-live">
          live <b className="font-mono font-semibold text-text">{versionLabel(status.version, versions)}</b> · {liveSentence(status, versions, me)}
        </span>
      )}
    </div>
  );
}

/** Banner when a file on disk does not validate: the gateway keeps the last good version (CONCEPT §11.1). */
function DiskInvalidBanner({ status, versions, onOpen }: { status: PolicyStatus; versions: PolicyVersion[] | undefined; onOpen: (file: string) => void }) {
  const errors = status.last_error;
  if (errors.length === 0) return null;
  const files = [...new Set(errors.map((e) => e.file).filter((f): f is string => !!f))];
  const what = files.length ? files.join(", ") : "A policy file";
  return (
    <StatusBox variant="warning" title={`${what} on disk ${files.length > 1 ? "are" : "is"} invalid. Rogatka keeps ${versionLabel(status.version, versions)}, the last good version.`}>
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {errors.map((e, i) => (
          <li key={i}>
            <span className="font-mono text-[12px] text-muted">
              {e.file ?? ""}
              {e.line ? ` L${e.line}` : ""}
              {e.path ? ` ${e.path}` : ""}
            </span>{" "}
            {e.message}
          </li>
        ))}
      </ul>
      <p className="m-0 mt-1 text-muted">New requests still use the last good version. Fix the file on disk, or open it here and save a valid version.</p>
      {files[0] && (
        <div className="mt-2">
          <Button size="sm" onClick={() => onOpen(files[0])}>
            Open {files[0]} in YAML
          </Button>
        </div>
      )}
    </StatusBox>
  );
}

export function PoliciesScreen() {
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("rules"));
  const [{ rule, file, q }, setParams] = useQueryStates({
    rule: parseAsString,
    file: parseAsString.withDefault("controls.yaml"),
    q: parseAsString.withDefault(""),
  });
  const status = usePolicyStatus();
  const versions = usePolicyVersions();
  const fileCount = status.data?.files.map((f) => f.name.replace(/\.yaml$/, ""));

  const openYaml = (name: string, ruleId?: string) => {
    void setTab("yaml");
    void setParams({ file: name, ...(ruleId ? { rule: ruleId } : {}) });
  };

  return (
    <>
      <LiveHeader status={status.data} versions={versions.data} />
      {status.data && <DiskInvalidBanner status={status.data} versions={versions.data} onOpen={(f) => openYaml(f)} />}
      {status.isError && (
        <StatusBox variant="error" title="Could not load the policy status">
          The policy service did not answer. Reading and publishing need the gateway&rsquo;s policy service.
        </StatusBox>
      )}
      <FilterRow>
        <SegmentedTabs
          ariaLabel="View"
          value={tab}
          onChange={(t) => void setTab(t)}
          tabs={[
            { value: "rules", label: "Rules" },
            { value: "yaml", label: "YAML" },
            { value: "history", label: "History" },
          ]}
        />
        {tab === "rules" && (
          <SearchInput value={q} onChange={(v) => void setParams({ q: v || null })} placeholder="Rule ID or topic" ariaLabel="Search rules" />
        )}
        <FilterSpacer />
        {fileCount && <span className="text-[12px] text-muted">files: {fileCount.join(" · ")}</span>}
      </FilterRow>
      {tab === "rules" && (
        <RulesTab ruleId={rule} onSelectRule={(id) => void setParams({ rule: id })} query={q} onOpenYaml={(r) => openYaml(r.file, r.id)} />
      )}
      {tab === "yaml" && (
        <YamlTab file={file} onFileChange={(name) => void setParams({ file: name })} ruleId={rule} onSelectRule={(id) => void setParams({ rule: id })} />
      )}
      {tab === "history" && <HistoryTab />}
    </>
  );
}
