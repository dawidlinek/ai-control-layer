"use client";

/**
 * The real YAML editor: Monaco (bundled, no CDN), YAML highlighting, rule / org-lock decorations and problem markers.
 * Imported only through `yaml-editor.tsx` (next/dynamic, ssr: false).
 *
 * Schema checks run in the page (`schema-check.ts`, against `GET /policy/schema`) and arrive here as `errors`.
 * monaco-yaml's language worker is not wired: its dependency monaco-worker-manager imports
 * `monaco-editor/esm/vs/editor/editor.worker.js`, which monaco-editor 0.57's `exports` map does not resolve, so
 * bundling it needs a webpack alias in next.config.ts (see the Policies report).
 */
import * as React from "react";
import Editor, { loader, type OnMount } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import { useTheme } from "@/components/shell/theme";
import { ICON_PATHS } from "@/components/rogatka";
import type { YamlEditorProps } from "./yaml-editor";

// Web worker for the editor services (webpack 5 / Next resolve this URL and bundle the worker).
if (typeof window !== "undefined") {
  (window as unknown as { MonacoEnvironment: monaco.Environment }).MonacoEnvironment = {
    getWorker() {
      return new Worker(new URL("monaco-editor/editor/editor.worker", import.meta.url));
    },
  };
  loader.config({ monaco });
}

/** Monaco needs literal colours: read them from the design tokens so both themes match the app. */
function cssVar(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return /^#[0-9a-f]{6}$/i.test(v) ? v : fallback;
}

function defineTheme(dark: boolean): string {
  const name = dark ? "rogatka-dark" : "rogatka-light";
  const hex = (n: string, f: string) => cssVar(n, f).slice(1);
  monaco.editor.defineTheme(name, {
    base: dark ? "vs-dark" : "vs",
    inherit: true,
    rules: [
      { token: "type", foreground: hex("--dec-route-local", dark ? "#7cb4ff" : "#1d4ed8") },
      { token: "string", foreground: hex("--dec-downgrade", dark ? "#fbbf24" : "#a16207") },
      { token: "number", foreground: hex("--dec-sanitize", dark ? "#2dd4bf" : "#0f766e") },
      { token: "keyword", foreground: hex("--dec-pseudonymise", dark ? "#b4a0ff" : "#6d28d9") },
      { token: "comment", foreground: hex("--muted", dark ? "#9ba4ae" : "#56606b"), fontStyle: "italic" },
    ],
    colors: {
      "editor.background": cssVar("--inset", dark ? "#101215" : "#eceef1"),
      "editor.foreground": cssVar("--text", dark ? "#e7e9ec" : "#14171b"),
      "editorLineNumber.foreground": cssVar("--muted", dark ? "#9ba4ae" : "#56606b"),
      "editorGutter.background": cssVar("--inset", dark ? "#101215" : "#eceef1"),
      "editorWidget.background": cssVar("--surface", dark ? "#15181c" : "#ffffff"),
      "editorWidget.border": cssVar("--border-strong", dark ? "#3a414a" : "#c3c9d1"),
    },
  });
  return name;
}

const LOCK_SVG = `url("data:image/svg+xml,${encodeURIComponent(
  `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'><path d='${ICON_PATHS.lock}'/></svg>`,
)}")`;

/** Decoration classes (colours from the design tokens). */
const DECORATION_CSS = `
.rg-yaml-sel { background: var(--accent-soft); box-shadow: inset 3px 0 0 var(--accent); }
.rg-yaml-lock { background: color-mix(in srgb, var(--dec-monitor) 9%, transparent); }
.rg-yaml-lock-glyph { background-color: var(--muted); -webkit-mask: ${LOCK_SVG} center / 11px no-repeat; mask: ${LOCK_SVG} center / 11px no-repeat; }
`;

export function MonacoYamlEditor({ fileName, value, onChange, readOnly, highlightLine, lockedLines, errors, ariaLabel }: YamlEditorProps) {
  const { theme } = useTheme();
  const editorRef = React.useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const decorations = React.useRef<monaco.editor.IEditorDecorationsCollection | null>(null);
  const [ready, setReady] = React.useState(false);

  const themeName = React.useMemo(() => (typeof window === "undefined" ? "vs-dark" : defineTheme(theme !== "light")), [theme]);

  const onMount: OnMount = (editor) => {
    editorRef.current = editor;
    decorations.current = editor.createDecorationsCollection();
    setReady(true);
  };

  // Highlighted rule line + org-lock lines.
  React.useEffect(() => {
    const editor = editorRef.current;
    if (!ready || !editor || !decorations.current) return;
    const items: monaco.editor.IModelDeltaDecoration[] = (lockedLines ?? []).map((l) => ({
      range: new monaco.Range(l, 1, l, 1),
      options: {
        isWholeLine: true,
        className: "rg-yaml-lock",
        glyphMarginClassName: "rg-yaml-lock-glyph",
        glyphMarginHoverMessage: { value: "Org lock: read-only in the panel. Change it in the file, with a review." },
      },
    }));
    if (highlightLine) {
      items.push({ range: new monaco.Range(highlightLine, 1, highlightLine, 1), options: { isWholeLine: true, className: "rg-yaml-sel" } });
    }
    decorations.current.set(items);
  }, [ready, lockedLines, highlightLine, value]);

  React.useEffect(() => {
    if (ready && highlightLine) editorRef.current?.revealLineInCenter(highlightLine);
  }, [ready, highlightLine, fileName]);

  // Problems (schema check as you type, or the gateway's Validate / Save errors) as markers.
  React.useEffect(() => {
    const model = editorRef.current?.getModel();
    if (!ready || !model) return;
    monaco.editor.setModelMarkers(
      model,
      "rogatka",
      (errors ?? []).map((e) => ({
        severity: monaco.MarkerSeverity.Error,
        message: e.message,
        startLineNumber: e.line,
        startColumn: e.column ?? 1,
        endLineNumber: e.line,
        endColumn: model.getLineMaxColumn(Math.min(e.line, model.getLineCount())),
      })),
    );
  }, [ready, errors, fileName]);

  return (
    <div className="h-[560px]" aria-label={ariaLabel} role="group">
      <style>{DECORATION_CSS}</style>
      <Editor
        path={`file:///policy/${fileName}`}
        language="yaml"
        value={value}
        theme={themeName}
        onChange={(v) => onChange(v ?? "")}
        onMount={onMount}
        loading={<span className="text-[12.5px] text-muted">Loading the editor…</span>}
        options={{
          readOnly,
          readOnlyMessage: { value: "Only admins can change policy." },
          glyphMargin: true,
          minimap: { enabled: false },
          fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
          fontSize: 12.5,
          lineHeight: 21,
          tabSize: 2,
          insertSpaces: true,
          scrollBeyondLastLine: false,
          renderWhitespace: "boundary",
          automaticLayout: true,
          ariaLabel,
        }}
      />
    </div>
  );
}
