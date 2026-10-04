import type { components } from "@/lib/api/schema";

/** The nine gateway decisions (contract `Action`). Always shown as icon + mono label, never colour alone. */
export type Decision = components["schemas"]["Action"];
/** Severity as used by chips. `info` exists in the contract but has no chip; it renders as `low`. */
export type Severity = "critical" | "high" | "medium" | "low";

export const DECISIONS: readonly Decision[] = [
  "allow",
  "monitor",
  "redact",
  "pseudonymise",
  "sanitize",
  "downgrade",
  "route_local",
  "require_approval",
  "block",
] as const;

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"] as const;

/** 24x24 stroke paths, copied from the DEC / SEV objects of the design prototypes. */
export const DECISION_ICON: Record<Decision, string> = {
  allow: "M5 12.5l4.5 4.5L19 7.5",
  monitor:
    "M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z M12 9.2a2.8 2.8 0 1 0 0 5.6 2.8 2.8 0 1 0 0-5.6z",
  redact: "M4 6h16v4H4z M4 14h7 M14 14h6 M4 18h16",
  pseudonymise: "M4 8h13 M14 4.5L17.5 8 14 11.5 M20 16H7 M10 12.5L6.5 16 10 19.5",
  sanitize: "M4 6h16 M7 12h10 M10 18h4",
  downgrade: "M12 4v15 M6 13l6 6 6-6",
  route_local: "M3.5 11L12 4.5l8.5 6.5 M6 9.5v10h12v-10 M10 19.5v-5h4v5",
  require_approval: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M12 7.5V12l3 2",
  block: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M6 6l12 12",
};

export const SEVERITY_ICON: Record<Severity, string> = {
  critical: "M12 3.5l9 16H3z M12 10v4.5 M12 17.5v.01",
  high: "M12 3.5l9 16H3z M12 10v4.5 M12 17.5v.01",
  medium: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M12 8v5 M12 16v.01",
  low: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M12 11v5 M12 8v.01",
};

/** CSS variable carrying the colour of each decision / severity (defined in globals.css, dark and light). */
export const DECISION_VAR: Record<Decision, string> = {
  allow: "var(--dec-allow)",
  monitor: "var(--dec-monitor)",
  redact: "var(--dec-redact)",
  pseudonymise: "var(--dec-pseudonymise)",
  sanitize: "var(--dec-sanitize)",
  downgrade: "var(--dec-downgrade)",
  route_local: "var(--dec-route-local)",
  require_approval: "var(--dec-require-approval)",
  block: "var(--dec-block)",
};

export const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

/** Literal Tailwind classes (so the scanner sees them): decision text colour and solid background (dots, chart bars). */
export const DECISION_TEXT_CLASS: Record<Decision, string> = {
  allow: "text-dec-allow",
  monitor: "text-dec-monitor",
  redact: "text-dec-redact",
  pseudonymise: "text-dec-pseudonymise",
  sanitize: "text-dec-sanitize",
  downgrade: "text-dec-downgrade",
  route_local: "text-dec-route-local",
  require_approval: "text-dec-require-approval",
  block: "text-dec-block",
};

export const DECISION_BG_CLASS: Record<Decision, string> = {
  allow: "bg-dec-allow",
  monitor: "bg-dec-monitor",
  redact: "bg-dec-redact",
  pseudonymise: "bg-dec-pseudonymise",
  sanitize: "bg-dec-sanitize",
  downgrade: "bg-dec-downgrade",
  route_local: "bg-dec-route-local",
  require_approval: "bg-dec-require-approval",
  block: "bg-dec-block",
};

/** Map any contract severity (incl. `info`) onto a chip severity. */
export function toSeverity(s: string | null | undefined): Severity {
  return s === "critical" || s === "high" || s === "medium" ? s : "low";
}
