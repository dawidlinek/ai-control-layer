"use client";

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ErrorState, ListWithSidebar, LoadingRows, Segmented, StatusBox, linkClass } from "@/components/rogatka";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useHasRole } from "@/lib/auth/user-context";
import type { PolicyError } from "@/lib/api/types";
import { ApiError } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";
import { usePolicyFile, usePolicyFiles, usePolicySchema, usePolicyStatus, usePolicyVersions, useRuleHits, useValidatePolicy, useWritePolicyFile } from "./api";
import { errorMessage, isConflict, nextVersionLabel, versionLabel } from "./helpers";
import { RuleSidebar } from "./rule-sidebar";
import { checkPolicyYaml } from "./schema-check";
import { lineOfId, lockedLines } from "./rules";
import { usePolicyRules } from "./use-rules";
import { YamlEditor } from "./yaml-editor";

type Drafts = Record<string, { base: string; text: string }>;

function ErrorList({ errors, onJump }: { errors: readonly PolicyError[]; onJump: (e: PolicyError) => void }) {
  return (
    <ul aria-label="Problems" className="m-0 flex list-none flex-col gap-1 p-0">
      {errors.map((e, i) => (
        <li key={i} className="flex flex-wrap items-baseline gap-1.5">
          {e.line ? (
            <button type="button" onClick={() => onJump(e)} className={`${linkClass} border-0 bg-transparent p-0 font-mono text-[12px]`}>
              {e.file ? `${e.file} ` : ""}L{e.line}
            </button>
          ) : (
            e.file && <span className="font-mono text-[12px] text-muted">{e.file}</span>
          )}
          {e.path && <span className="font-mono text-[12px] text-muted">{e.path}</span>}
          <span>{e.message}</span>
        </li>
      ))}
    </ul>
  );
}

function writeErrors(err: unknown): PolicyError[] {
  if (!(err instanceof ApiError)) return [];
  const b = err.body as { details?: { errors?: PolicyError[] } } | undefined;
  return Array.isArray(b?.details?.errors) ? b.details.errors : [];
}

export function YamlTab({
  file,
  onFileChange,
  ruleId,
  onSelectRule,
}: {
  file: string;
  onFileChange: (name: string) => void;
  ruleId: string | null;
  onSelectRule: (id: string | null) => void;
}) {
  const canEdit = useHasRole("admin");
  const canValidate = useHasRole("analyst");
  const qc = useQueryClient();
  const status = usePolicyStatus();
  const files = usePolicyFiles();
  const current = usePolicyFile(file);
  const schema = usePolicySchema();
  const versions = usePolicyVersions();
  const { rules, controls } = usePolicyRules();
  const hits = useRuleHits();
  const validate = useValidatePolicy();
  const save = useWritePolicyFile();
  const [drafts, setDrafts] = React.useState<Drafts>({});
  const [note, setNote] = React.useState("");
  const [noteError, setNoteError] = React.useState(false);
  const [jump, setJump] = React.useState<number | null>(null);
  const [saved, setSaved] = React.useState<string | null>(null);

  const data = current.data;
  const draft = drafts[file];
  const text = draft?.text ?? data?.content ?? "";
  const dirty = !!data && draft !== undefined && draft.text !== data.content;
  const baseVersion = draft?.base ?? data?.version ?? "";

  const selectedRule = rules?.find((r) => r.id === ruleId);
  const ruleLine = ruleId && selectedRule?.file === file ? lineOfId(text, ruleId) : null;
  const locked = React.useMemo(() => lockedLines(file, text, status.data?.locked_controls ?? []), [file, text, status.data?.locked_controls]);
  const live = status.data ? versionLabel(status.data.version, versions.data) : "";
  const next = nextVersionLabel(versions.data);

  const resetResults = () => {
    validate.reset();
    save.reset();
    setSaved(null);
  };

  const onChange = (value: string) => {
    if (!data) return;
    setDrafts((d) => ({ ...d, [file]: { base: d[file]?.base ?? data.version, text: value } }));
    if (validate.data || save.isError) resetResults();
  };

  const reload = async () => {
    setDrafts((d) => {
      const { [file]: _dropped, ...rest } = d;
      return rest;
    });
    resetResults();
    await qc.invalidateQueries({ queryKey: queryKeys.policy.all });
  };

  const onValidate = () => {
    setSaved(null);
    save.reset();
    validate.mutate({ [file]: text });
  };

  const onSave = () => {
    if (!note.trim()) {
      setNoteError(true);
      return;
    }
    setNoteError(false);
    validate.reset();
    save.mutate(
      { name: file, content: text, baseVersion, message: note.trim() },
      {
        onSuccess: (s) => {
          setSaved(versionLabel(s.version, versions.data));
          setNote("");
          setDrafts((d) => {
            const { [file]: _done, ...rest } = d;
            return rest;
          });
        },
      },
    );
  };

  const errors: PolicyError[] = validate.data?.errors ?? writeErrors(save.error);
  // Schema check as you type (the gateway's Validate / Save errors win while they are shown).
  const deferred = React.useDeferredValue(text);
  const typing = React.useMemo(() => (data ? checkPolicyYaml(deferred, schema.data) : []), [data, deferred, schema.data]);
  const serverMarkers = errors.filter((e) => e.line && (!e.file || e.file === file)).map((e) => ({ line: e.line!, column: e.column, message: e.message }));
  const markers = errors.length ? serverMarkers : typing;
  const fileNames = (files.data ?? status.data?.files ?? []).map((f) => f.name);

  const editor = (
    <div className="overflow-hidden rounded-[8px] border border-border bg-inset">
      <div className="flex flex-wrap items-center gap-2.5 border-b border-border bg-surface px-3 py-2">
        <Segmented
          ariaLabel="File"
          size="sm"
          value={file}
          onChange={(n) => {
            setJump(null);
            resetResults();
            onFileChange(n);
          }}
          options={fileNames.map((n) => ({ value: n, label: <span className="font-mono">{n}</span> }))}
        />
        <span className="text-[12px] text-muted">
          {live} · checked against the schema as you type
          {data && (
            <span data-testid="typing-check" className={typing.length ? "text-dec-block" : undefined}>
              {" · "}
              {typing.length === 0 ? "no problems" : `${typing.length} ${typing.length === 1 ? "problem" : "problems"}`}
            </span>
          )}
          {dirty && <b className="ml-1.5 font-medium text-dec-downgrade">· unsaved changes</b>}
        </span>
      </div>
      {current.isPending ? (
        <LoadingRows rows={8} />
      ) : current.isError ? (
        <ErrorState error={current.error} onRetry={() => void current.refetch()} />
      ) : (
        <YamlEditor
          fileName={file}
          value={text}
          onChange={onChange}
          readOnly={!canEdit}
          highlightLine={jump ?? ruleLine}
          lockedLines={locked}
          errors={markers}
          ariaLabel={`${file} editor`}
        />
      )}
      <div className="flex flex-col gap-2 border-t border-border bg-surface px-3 py-2.5">
        {typing.length > 0 && !validate.data && !save.isError && (
          <div className="flex flex-col gap-1 text-[13px]" aria-label="Problems as you type" role="region">
            <b className="font-semibold text-dec-block">
              {typing.length} {typing.length === 1 ? "problem" : "problems"} as you type
            </b>
            <ErrorList errors={typing.map((t) => ({ file, line: t.line, column: t.column ?? null, path: t.path, message: t.message }))} onJump={(e) => setJump(e.line ?? null)} />
          </div>
        )}
        {validate.isError && (
          <StatusBox variant="error" title="Could not validate">
            {errorMessage(validate.error)}
          </StatusBox>
        )}
        {validate.data &&
          (validate.data.valid ? (
            <StatusBox variant="success" title="No problems found">
              {file} matches the schema{validate.data.candidate_version ? ` · it would be saved as ${versionLabel(validate.data.candidate_version, versions.data)}` : ""}.
            </StatusBox>
          ) : (
            <StatusBox variant="error" title={`${validate.data.errors.length} ${validate.data.errors.length === 1 ? "problem" : "problems"} in ${file}`}>
              <ErrorList errors={validate.data.errors} onJump={(e) => setJump(e.line ?? null)} />
            </StatusBox>
          ))}
        {save.isError &&
          (isConflict(save.error) ? (
            <StatusBox variant="error" title={`${file} changed while you were editing`}>
              <p className="m-0">
                Your edit is based on an older version of the file. Live is now {live}. Reload the file to get the latest version, then apply your
                change again: Rogatka never overwrites a newer version.
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button size="sm" onClick={() => void reload()}>
                  Reload the file
                </Button>
                <Button size="sm" variant="ghost" onClick={() => save.reset()}>
                  Keep my text for now
                </Button>
              </div>
            </StatusBox>
          ) : (
            <StatusBox variant="error" title="Not saved">
              {writeErrors(save.error).length > 0 ? <ErrorList errors={writeErrors(save.error)} onJump={(e) => setJump(e.line ?? null)} /> : errorMessage(save.error)}
            </StatusBox>
          ))}
        {saved && (
          <StatusBox variant="success" title={`Saved as policy ${saved}`}>
            {file} is live · new requests use it now.
          </StatusBox>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {canEdit && (
            <Input
              aria-label="Note for history"
              placeholder="Note for history (required to save)"
              value={note}
              onChange={(e) => {
                setNote(e.target.value);
                if (e.target.value.trim()) setNoteError(false);
              }}
              className="max-w-[360px] flex-1"
            />
          )}
          <div className="flex-1" />
          <Button onClick={onValidate} disabled={!canValidate || validate.isPending || !data} title={canValidate ? undefined : "Analysts and admins can validate"}>
            {validate.isPending ? "Validating…" : "Validate"}
          </Button>
          {canEdit ? (
            <Button variant="primary" onClick={onSave} disabled={!dirty || save.isPending}>
              {save.isPending ? "Saving…" : next ? `Save as ${next}` : "Save"}
            </Button>
          ) : (
            <Button variant="primary" disabled title="Only admins can change policy">
              Save
            </Button>
          )}
        </div>
        {noteError && (
          <span role="alert" className="text-[12px] text-dec-block">
            Write a short note for the history.
          </span>
        )}
      </div>
    </div>
  );

  return (
    <ListWithSidebar
      open={!!selectedRule}
      onClose={() => onSelectRule(null)}
      sidebarLabel="Rule"
      list={editor}
      sidebar={selectedRule && <RuleSidebar rule={selectedRule} hits={hits.data} controlsFile={controls.data} onOpenYaml={selectedRule.file !== file ? () => onFileChange(selectedRule.file) : undefined} />}
    />
  );
}
