/** MSW handlers: feed domain (signature feed status + sync, signatures, add rule, model-file scans). */
import { http, HttpResponse, type HttpHandler } from "msw";
import type { FeedRuleCreate, FeedSignature } from "@/lib/api/types";
import { artifact, artifacts, feedServer, feedStatus, finding, pendingRules, signatures, type SeedSignature } from "../db/feed";
import { events } from "../db/events";
import type { ArtifactScanResult } from "../db/types";
import { adminPath, intParam, listResponse, problem, queryOf } from "./helpers";

const HOUR = 3600 * 1000;
const ID_PATTERN = /^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$/;

/** Deterministic stand-in for the scanner: pickle-like extensions are blocked, everything else passes. */
function scan(filename: string, size: number): ArtifactScanResult {
  const pickle = /\.(bin|pkl|pickle|pt|pth)$/i.test(filename);
  const n = artifacts.items.length + 1;
  return artifact({
    id: `art-${String(100 + n).padStart(4, "0")}`,
    filename,
    sha256: Array.from({ length: 64 }, (_, i) => ((i * 7 + n) % 16).toString(16)).join(""),
    size,
    format_detected: pickle ? "pickle" : (filename.split(".").pop() ?? "unknown"),
    verdict: pickle ? "blocked_format" : "safe",
    findings: pickle
      ? [finding("ART-PICKLE-01", "high", "pickle stream · blocked by default")]
      : [finding("ART-HEADER-01", "info", "header OK · no code found")],
    scanned_at: new Date().toISOString(),
  });
}

/** Decisions that cited the rule in the last 24 h, counted from the mock events (so live demo traffic moves the counter). */
function withHits(s: SeedSignature): FeedSignature {
  const since = new Date(Date.now() - 24 * HOUR).toISOString();
  const hits = events.items.filter((e) => e.rule_ids.includes(s.id) && e.timestamp >= since);
  const last = hits.reduce<string | null>((a, e) => (a === null || e.timestamp > a ? e.timestamp : a), null);
  return { ...s, hits_24h: hits.length, last_hit_at: last };
}

const TYPE_OF: Record<FeedRuleCreate["target"], FeedSignature["type"]> = {
  package: "package_version",
  domain: "ioc_domain",
  url: "url_path",
  command: "arg_pattern",
  tool_description: "regex",
  prompt_text: "regex",
  answer_text: "regex",
  any_text: "regex",
};

const STAGES_OF: Record<FeedRuleCreate["target"], FeedSignature["stages"]> = {
  package: ["tool_call"],
  domain: ["tool_call"],
  url: ["tool_call"],
  command: ["tool_call"],
  tool_description: ["mcp_tools_list"],
  prompt_text: ["ingress"],
  answer_text: ["egress"],
  any_text: ["ingress", "tool_result", "egress"],
};

function patternOf(b: FeedRuleCreate): string {
  if (b.target !== "package") return b.pattern ?? "";
  const versions = (b.versions ?? []).filter((v) => v && v !== "*");
  return `${b.ecosystem ?? "pypi"}: ${b.package}${versions.length ? ` == ${versions.join(" | ")}` : " (any version)"}`;
}

/** Moves rules the gateway has not loaded yet into the active bundle (what the gateway does on its next poll / "Sync now"). */
function applyPending(): void {
  if (pendingRules.items.length === 0) return;
  signatures.items.push(...pendingRules.items.splice(0));
  feedStatus.bundle_version = feedServer.bundle_version;
  feedStatus.entries = 214 + signatures.items.length - 7;
  feedStatus.issued_at = new Date().toISOString();
  feedStatus.loaded_at = new Date().toISOString();
}

export const feedHandlers: HttpHandler[] = [
  http.get(adminPath("/feed"), () => HttpResponse.json(feedStatus)),

  http.post(adminPath("/feed/sync"), () => {
    const at = new Date().toISOString();
    applyPending();
    feedStatus.last_sync_at = at;
    feedStatus.verified = true;
    feedStatus.last_error = null;
    return HttpResponse.json(feedStatus);
  }),

  http.get(adminPath("/feed/signatures"), ({ request }) => {
    const q = queryOf(request);
    const target = q.get("target");
    const text = q.get("q")?.trim().toLowerCase();
    const matching = signatures.items
      .filter((s) => (target ? s.target === target : true))
      .filter((s) => (text ? [s.id, s.title, s.description, s.pattern, s.source].some((v) => v.toLowerCase().includes(text)) : true));
    return listResponse(matching.slice(0, intParam(q, "limit", 500, 5000)).map(withHits), matching.length);
  }),

  http.post(adminPath("/feed/rules"), async ({ request }) => {
    const b = (await request.json()) as FeedRuleCreate;
    if (!ID_PATTERN.test(b.id ?? "")) return problem(422, "id does not match the rule id pattern");
    if (!b.description || b.description.trim().length < 3) return problem(422, "description must be at least 3 characters");
    if (b.target === "package") {
      if (!b.package?.trim()) return problem(422, "package is required for the package target");
    } else {
      if (!b.pattern?.trim()) return problem(422, `pattern is required for the ${b.target} target`);
      if (b.target !== "domain") {
        try {
          new RegExp(b.pattern);
        } catch {
          return problem(422, `invalid regular expression: ${b.pattern}`);
        }
      }
    }
    if ([...signatures.items, ...pendingRules.items].some((s) => s.id === b.id)) return problem(409, `rule ${b.id} already exists`);

    const description = b.description.trim();
    const title = description.split(/(?<=[.!?])\s/)[0];
    const rule: SeedSignature = {
      id: b.id,
      title: title.length <= 120 ? title : `${title.slice(0, 119)}…`,
      description,
      target: b.target,
      type: TYPE_OF[b.target],
      pattern: patternOf(b),
      action: b.action ?? "block",
      severity: b.severity ?? "high",
      stages: STAGES_OF[b.target],
      source: b.source ?? "panel",
      reference: b.cve?.[0] ?? null,
      cve: b.cve ?? [],
      owasp: b.owasp ?? [],
      atlas_technique: b.atlas_technique ?? [],
      origin: "feed",
      expires: b.expires ?? null,
      expired: false,
    };
    feedServer.bundle_version += 1;
    const sync = b.sync_now ?? true;
    pendingRules.items.push(rule);
    if (sync) {
      applyPending();
      feedStatus.last_sync_at = new Date().toISOString();
    }
    return HttpResponse.json({ rule: withHits(rule), bundle_version: feedServer.bundle_version, synced: sync, feed: feedStatus }, { status: 201 });
  }),

  http.get(adminPath("/artifacts"), () =>
    HttpResponse.json([...artifacts.items].sort((a, b) => b.scanned_at.localeCompare(a.scanned_at))),
  ),

  http.post(adminPath("/artifacts/scan"), async ({ request }) => {
    const form = await request.formData().catch(() => null);
    const file = form?.get("file");
    if (!file || typeof file === "string") return problem(422, "file is required");
    const result = scan(file.name, file.size);
    artifacts.items.unshift(result);
    return HttpResponse.json(result);
  }),
];
