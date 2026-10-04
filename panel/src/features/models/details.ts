/**
 * Readers for the Models screen. The contract's `ModelInfo` has no fields for "who can use it", "how auto picks it",
 * the model file or a description; the demo gateway / mock put them in the free-form `tags` map. Every reader tolerates
 * missing keys (the real gateway may not send them) and falls back to text derived from the typed fields.
 */
import { formatNumber, formatUsd } from "@/lib/format";
import type { ConnectorStatus, ModelInfo } from "@/lib/api/types";

/** Tag keys that carry demo details (not shown as plain tags). */
const DETAIL_KEYS = new Set(["about", "who", "auto_share", "auto_reasons", "model_file", "limit", "guard", "role", "auto_how"]);

export interface WhoEntry {
  label: string;
  how: string;
  href: string | null;
  /** A personal grant (accent border). */
  grant: boolean;
}

export interface AutoReason {
  label: string;
  count: string;
}

function pairs(raw: string | undefined): Array<[string, string]> {
  if (!raw) return [];
  return raw
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.lastIndexOf("=");
      return i < 0 ? [p, ""] : [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    });
}

export function isGuardModel(m: ModelInfo): boolean {
  if (m.tags.guard) return true;
  const role = (m.role ?? m.tags.role ?? "").toLowerCase();
  return role.startsWith("embedding") || role === "judge";
}

export function connectorName(id: string): string {
  return id.charAt(0).toUpperCase() + id.slice(1);
}

export function dataClassesText(classes: readonly string[]): string {
  if (classes.length === 0) return "nothing";
  if (["public", "internal", "confidential", "restricted"].every((c) => classes.includes(c))) return "all classes";
  return classes.join(", ");
}

export function priceText(m: ModelInfo): string {
  const p = m.pricing;
  if (p.in_per_1k !== undefined || p.out_per_1k !== undefined) {
    return `${p.in_per_1k ?? 0} / ${p.out_per_1k ?? 0} USD per 1k tokens in / out`;
  }
  if (p.usd_per_gpu_second !== undefined) return `${p.usd_per_gpu_second} USD per GPU-second`;
  return "—";
}

export function usageText(m: ModelInfo): string {
  return m.tier === "cloud" ? `${formatUsd(m.usd_day)} USD` : `${formatNumber(m.gpu_seconds_day)} GPU-s`;
}

export function roleText(m: ModelInfo): string {
  return m.role ?? m.tags.role ?? (m.tier === "cloud" ? "cloud model" : "local model");
}

export function aboutText(m: ModelInfo): string {
  if (m.tags.about) return m.tags.about;
  const where = m.tier === "cloud" ? `in the cloud through the ${m.connector} connector` : `on the local ${m.connector} connector`;
  return `${m.id} runs ${where}. It may get ${dataClassesText(m.data_classes)} data.`;
}

export function otherTags(m: ModelInfo): string {
  const t = Object.entries(m.tags).filter(([k]) => !DETAIL_KEYS.has(k));
  return t.length ? t.map(([k, v]) => `${k}: ${v}`).join(", ") : "—";
}

function whoHref(label: string, how: string): string | null {
  const grant = /\b(g-\d+)\b/.exec(how)?.[1];
  if (grant) return `/grants?sel=${grant}`;
  if (/group/.test(how)) return `/users?tab=groups&sel=${encodeURIComponent(label)}`;
  return null;
}

export function whoCanUse(m: ModelInfo): WhoEntry[] {
  return pairs(m.tags.who).map(([label, how]) => ({ label, how, href: whoHref(label, how), grant: /grant/.test(how) }));
}

export function autoShare(m: ModelInfo): string | null {
  return m.tags.auto_share ?? null;
}

export function autoReasons(m: ModelInfo): AutoReason[] {
  return pairs(m.tags.auto_reasons).map(([label, count]) => ({
    label,
    count: Number.isFinite(Number(count)) && count !== "" ? formatNumber(Number(count)) : count,
  }));
}

/** One plain sentence on why auto picks this model (specialists); null when the gateway sends nothing. */
export function autoHow(m: ModelInfo): string | null {
  if (m.tags.auto_how) return m.tags.auto_how;
  if (m.tags.task === "polish_legal") {
    return "A fixed detector decides, with no model call: Polish wording combined with legal vocabulary or article citations such as art. 415 k.c. Confidential Polish legal text stays on Bielik. If Bielik is not available or you have no access to it, auto uses the normal rules instead (confidential data stays on local Qwen).";
  }
  return null;
}

export function modelFileName(m: ModelInfo): string | null {
  return m.tags.model_file ?? null;
}

/** "Data it may get" etc. for the File check column. */
export function fileCheck(m: ModelInfo): { label: string; ok: boolean | null } {
  switch (m.artifact_status) {
    case "scanned_ok":
      return { label: "passed", ok: true };
    case "scanned_bad":
      return { label: "blocked", ok: false };
    case "unscanned":
      return { label: "not scanned", ok: null };
    default:
      return { label: m.tier === "cloud" ? "API" : "—", ok: null };
  }
}

/** Is a model switched off because its connector's kill switch is engaged (or the model is disabled)? */
export function isModelOff(m: ModelInfo, connectors: readonly ConnectorStatus[]): boolean {
  const c = connectors.find((x) => x.id === m.connector);
  return !m.enabled || !m.available || !!c?.kill_switch || c?.enabled === false;
}

export function aliasesOf(models: readonly ModelInfo[], connectorId: string): string[] {
  return models.filter((m) => m.connector === connectorId && !isGuardModel(m)).flatMap((m) => m.aliases);
}

export function joinAnd(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
