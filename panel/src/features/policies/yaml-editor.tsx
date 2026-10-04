"use client";

import dynamic from "next/dynamic";

export interface YamlEditorProps {
  /** File name (`controls.yaml`): the model path, so the schema and the modeline resolve. */
  fileName: string;
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  /** 1-based line to highlight and scroll to (the selected rule). */
  highlightLine?: number | null;
  /** 1-based lines that belong to org locks (lock glyph + tint). */
  lockedLines?: readonly number[];
  /** Problems to show as markers (line-based): the schema check as you type, or the gateway's errors. */
  errors?: readonly { line: number; column?: number | null; message: string }[];
  /** Accessible label. */
  ariaLabel: string;
}

function EditorLoading() {
  return (
    <div role="status" className="flex h-[560px] items-center justify-center bg-inset text-[12.5px] text-muted">
      Loading the editor…
    </div>
  );
}

/**
 * Monaco, loaded only in the browser (it needs `window` and web workers). Tests mock this module
 * with a textarea (Monaco cannot run in jsdom).
 */
export const YamlEditor = dynamic<YamlEditorProps>(() => import("./monaco-yaml-editor").then((m) => m.MonacoYamlEditor), {
  ssr: false,
  loading: EditorLoading,
});
