import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { DECISIONS, DECISION_BG_CLASS, DECISION_ICON, DECISION_TEXT_CLASS, DECISION_VAR, SEVERITIES, SEVERITY_ICON, SEVERITY_VAR } from "./decisions";

const css = fs.readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8");
const block = (selector: string) => {
  const start = css.indexOf(selector);
  return css.slice(start, css.indexOf("\n}", start));
};
const dark = block(":root {");
const light = block(':root[data-theme="light"] {');

describe("design tokens (HANDOFF section 4)", () => {
  it.each([
    ["--bg", "#0e1013", "#f3f4f6"],
    ["--surface", "#15181c", "#ffffff"],
    ["--raised", "#1c2025", "#f6f7f9"],
    ["--inset", "#101215", "#eceef1"],
    ["--border", "#272c33", "#dce0e5"],
    ["--border-strong", "#3a414a", "#c3c9d1"],
    ["--text", "#e7e9ec", "#14171b"],
    ["--muted", "#9ba4ae", "#56606b"],
    ["--accent", "#4c8dff", "#3460ad"],
    ["--on-accent", "#0e1013", "#ffffff"],
    ["--dec-allow", "#4ade80", "#15803d"],
    ["--dec-monitor", "#a3b1c2", "#475569"],
    ["--dec-redact", "#d8a4fe", "#7e22ce"],
    ["--dec-pseudonymise", "#b4a0ff", "#6d28d9"],
    ["--dec-sanitize", "#2dd4bf", "#0f766e"],
    ["--dec-downgrade", "#fbbf24", "#a16207"],
    ["--dec-route-local", "#7cb4ff", "#1d4ed8"],
    ["--dec-require-approval", "#fb923c", "#c2410c"],
    ["--dec-block", "#f87171", "#b91c1c"],
    ["--sev-critical", "#fb7185", "#be123c"],
    ["--sev-high", "#f87171", "#b91c1c"],
    ["--sev-medium", "#fbbf24", "#a16207"],
    ["--sev-low", "#a3b1c2", "#475569"],
  ])("%s is %s (dark) and %s (light)", (name, d, l) => {
    expect(dark).toContain(`${name}: ${d};`);
    expect(light).toContain(`${name}: ${l};`);
  });

  it("tints chips 14 % / 32 % in dark and 10 % / 30 % in light", () => {
    expect(dark).toContain("--tint-bg: 14%;");
    expect(dark).toContain("--tint-bd: 32%;");
    expect(light).toContain("--tint-bg: 10%;");
    expect(light).toContain("--tint-bd: 30%;");
  });

  it("maps every token into the Tailwind theme", () => {
    for (const name of ["bg", "surface", "raised", "inset", "border", "border-strong", "text", "muted", "accent", "on-accent", "accent-soft"]) {
      expect(css).toContain(`--color-${name}: var(--${name});`);
    }
    for (const d of DECISIONS) expect(css).toContain(`--color-dec-${d.replace("_", "-")}:`);
    for (const s of SEVERITIES) expect(css).toContain(`--color-sev-${s}:`);
  });

  it("uses the 13 px / 1.45 base with the Plex fonts", () => {
    expect(css).toMatch(/font-size: 13px;\s*line-height: 1.45;/);
    expect(css).toContain("--font-plex-sans");
    expect(css).toContain("--font-plex-mono");
  });
});

describe("decision / severity vocabulary", () => {
  it("has the nine decisions, each with icon, colour and literal Tailwind classes", () => {
    expect(DECISIONS).toHaveLength(9);
    for (const d of DECISIONS) {
      expect(DECISION_ICON[d]).toBeTruthy();
      expect(DECISION_VAR[d]).toMatch(/^var\(--dec-/);
      expect(DECISION_TEXT_CLASS[d]).toMatch(/^text-dec-/);
      expect(DECISION_BG_CLASS[d]).toMatch(/^bg-dec-/);
    }
  });
  it("has four severities", () => {
    for (const s of SEVERITIES) {
      expect(SEVERITY_ICON[s]).toBeTruthy();
      expect(SEVERITY_VAR[s]).toBe(`var(--sev-${s})`);
    }
  });
});
