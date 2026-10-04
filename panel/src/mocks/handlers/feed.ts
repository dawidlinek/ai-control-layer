/** MSW handlers: feed domain (signature feed status + sync, model-file scans). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { artifacts, feedStatus } from "../db/feed";
import type { ArtifactScanResult } from "../db/types";
import { adminPath, problem } from "./helpers";

/** Deterministic stand-in for the scanner: pickle-like extensions are blocked, everything else passes. */
function scan(filename: string, size: number): ArtifactScanResult {
  const pickle = /\.(bin|pkl|pickle|pt|pth)$/i.test(filename);
  const n = artifacts.items.length + 1;
  return {
    id: `art-${String(100 + n).padStart(4, "0")}`,
    filename,
    sha256: Array.from({ length: 64 }, (_, i) => ((i * 7 + n) % 16).toString(16)).join(""),
    size,
    format_detected: pickle ? "pickle" : (filename.split(".").pop() ?? "unknown"),
    verdict: pickle ? "blocked_format" : "safe",
    findings: pickle
      ? [{ rule_id: "ART-PICKLE-01", severity: "high", message: "pickle stream · blocked by default" }]
      : [{ rule_id: "ART-HEADER-01", severity: "info", message: "header OK · no code found" }],
    scanned_at: new Date().toISOString(),
  };
}

export const feedHandlers: HttpHandler[] = [
  http.get(adminPath("/feed"), () => HttpResponse.json(feedStatus)),

  http.post(adminPath("/feed/sync"), () => {
    const at = new Date().toISOString();
    feedStatus.last_sync_at = at;
    feedStatus.verified = true;
    feedStatus.last_error = null;
    return HttpResponse.json(feedStatus);
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
