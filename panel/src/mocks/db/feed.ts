/**
 * Mock data: feed domain (signature feed status, the signatures of the active bundle, model-file scans). Demo data from
 * docs/ux/design-reference/FeedArtifacts.dc.html, model files updated to the HANDOFF section 7.1 lineup.
 * Endpoints: /admin/v1/feed (+ sync), /admin/v1/feed/signatures, /admin/v1/feed/rules, /admin/v1/artifacts (+ scan).
 */
import { daysAgo, demoClock, hoursAgo, secondsAgo } from "../time";
import { registerReset, seeded } from "./registry";
import type { ArtifactFinding, FeedSignature } from "@/lib/api/types";
import type { ArtifactScanResult, FeedStatus } from "./types";

function seedFeed(): FeedStatus {
  return {
    source_url: "http://feed.corp:8080/bundle.json",
    bundle_version: 412,
    issued_at: hoursAgo(3),
    loaded_at: hoursAgo(3),
    entries: 214,
    verified: true,
    last_sync_at: secondsAgo(30),
    last_error: null,
  };
}

/** Mutable on purpose: `POST /feed/sync` updates the sync time. */
export const feedStatus: FeedStatus = seedFeed();
registerReset(() => {
  Object.assign(feedStatus, seedFeed());
});

/** An `ArtifactFinding` with the optional fields filled (the gateway always sends them). */
export function finding(rule_id: string, severity: ArtifactFinding["severity"], message: string): ArtifactFinding {
  return { rule_id, severity, message, detail: null, cve: [] };
}

type ArtifactScanInput = Omit<ArtifactScanResult, "source" | "exception" | "model_ids" | "decision_id" | "scanned_by"> & Partial<ArtifactScanResult>;

/** An `ArtifactScanResult` with the optional fields filled (the gateway always sends them). */
export function artifact(a: ArtifactScanInput): ArtifactScanResult {
  return { source: "upload", exception: null, model_ids: [], decision_id: null, scanned_by: null, ...a };
}

const SHA = {
  qwen: "3d0a6e1c94b27f58a1d03e6c7b9f42d815a6c0e37b2d94f1a8e5c6b70d3291c2",
  deberta: "55c9b1e07a3f6d2894c1e5a7b30f9d6e2c48a1b7f05e3d96c2a8b4f1e70de204",
  gliner: "0f12a7c3e9b45d81f6c0a2e47b93d5f18c6e0a2b4d7f93c15e8a6b2d0f4cc8d1",
  bge: "c8d17a2e5f03b96c4d1e8a7f20b5c39e6d4a1f87b0c2e53d9a6f4b1e7c08a0f12",
  pickle: "a4f1e8c27b03d95f6a1c4e8b2d7f03a96c5e1b4d8f2a7c03e9b6d1f4a8c20c77",
  zip: "9e20b4d7f1a3c86e2b5d09f4a7c1e83b6d2f5a0c9e4b17d3f8a2c6e05b9db511",
  keras: "61c3f0a8d2e5b74c9a1f36e0d8b2c57a4e9f1d03b6c8a2e7f45d0b19c3a6e8a2",
};

function seedArtifactsRaw(): ArtifactScanInput[] {
  return [
    {
      id: "art-0007",
      filename: "finetune-v2.bin",
      sha256: SHA.pickle,
      size: 48_210_944,
      format_detected: "pickle",
      verdict: "malicious",
      findings: [finding("ART-PICKLE-01", "critical", 'GLOBAL os.system\nREDUCE → os.system("curl http://… | sh")')],
      scanned_at: daysAgo(3),
    },
    {
      id: "art-0008",
      filename: "adapter-weights.7z",
      sha256: SHA.zip,
      size: 12_582_912,
      format_detected: "7z",
      verdict: "blocked_format",
      findings: [finding("ART-FORMAT-01", "high", "expected ZIP (PyTorch) · found 7z header 37 7A BC AF")],
      scanned_at: daysAgo(3),
    },
    {
      id: "art-0005",
      filename: "intent-classifier.keras",
      sha256: SHA.keras,
      size: 3_407_872,
      format_detected: "Keras",
      verdict: "malicious",
      findings: [finding("ART-KERAS-01", "high", "layer 7: Lambda(function=…) · module reference builtins.exec")],
      scanned_at: daysAgo(6),
    },
    {
      id: "art-0012",
      filename: "qwen3.8-27b-instruct-q4_k_m.gguf",
      sha256: SHA.qwen,
      size: 16_811_294_720,
      format_detected: "GGUF",
      verdict: "safe",
      findings: [finding("ART-GGUF-01", "info", "GGUF v3 · 64 tensor groups · metadata within limits · pinned revision")],
      scanned_at: demoClock("08:10:00"),
    },
    {
      id: "art-0011",
      filename: "deberta-v3-injection.onnx",
      sha256: SHA.deberta,
      size: 738_197_504,
      format_detected: "ONNX",
      verdict: "safe",
      findings: [finding("ART-ONNX-01", "info", "ONNX opset 17 · no custom operators · no external data")],
      scanned_at: demoClock("08:11:00"),
    },
    {
      id: "art-0010",
      filename: "gliner-pii.safetensors",
      sha256: SHA.gliner,
      size: 611_319_808,
      format_detected: "safetensors",
      verdict: "safe",
      findings: [finding("ART-SAFETENSORS-01", "info", "safetensors header OK · tensors only, no code")],
      scanned_at: demoClock("08:11:30"),
    },
    {
      id: "art-0009",
      filename: "bge-m3.gguf",
      sha256: SHA.bge,
      size: 1_157_627_904,
      format_detected: "GGUF",
      verdict: "safe",
      findings: [finding("ART-GGUF-01", "info", "GGUF v3 · metadata within limits")],
      scanned_at: demoClock("08:12:00"),
    },
  ];
}

export const artifacts = seeded(() => seedArtifactsRaw().map(artifact));

// ---------------------------------------------------------------------------------------------------------------
// Signatures of the active bundle (GET /feed/signatures). Hits are not stored: the handler counts them from the events.

export type SeedSignature = Omit<FeedSignature, "hits_24h" | "last_hit_at">;

function sig(s: Partial<SeedSignature> & Pick<SeedSignature, "id" | "description" | "target" | "type" | "pattern">): SeedSignature {
  const title = s.description.split(/(?<=[.!?])\s/)[0];
  return {
    title: title.length <= 120 ? title : `${title.slice(0, 119)}…`,
    action: "block",
    severity: "high",
    stages: ["tool_call"],
    source: "",
    reference: null,
    cve: [],
    owasp: [],
    atlas_technique: [],
    origin: "feed",
    expires: null,
    expired: false,
    ...s,
  };
}

function seedSignatures(): SeedSignature[] {
  return [
    sig({
      id: "FEED-PKG-0007",
      description: "Blocks installing the two litellm releases that were published with a backdoor.",
      target: "package",
      type: "package_version",
      pattern: "pypi: litellm == 1.82.7 | 1.82.8",
      severity: "critical",
      source: "OSV · March 2026",
      atlas_technique: ["AML.T0010"],
      owasp: ["LLM03"],
    }),
    sig({
      id: "FEED-PKG-0012",
      description: "Blocks typosquatted packages such as “openal” or “langchian”.",
      target: "package",
      type: "package_version",
      pattern: "pypi|npm: openal, langchian, transformerss, …",
      severity: "medium",
      source: "internal list",
      atlas_technique: ["AML.T0010"],
      owasp: ["LLM03"],
    }),
    sig({
      id: "FEED-PKG-0142",
      description: "Blocks installing the fake torchtriton package used in a dependency-confusion attack.",
      target: "package",
      type: "package_version",
      pattern: "pypi: torchtriton (any version)",
      severity: "critical",
      source: "OSV · PyTorch advisory",
      atlas_technique: ["AML.T0010"],
      owasp: ["LLM03"],
    }),
    sig({
      id: "FEED-EXF-0044",
      description: "Removes markdown images and links whose address carries encoded data to an outside site.",
      target: "answer_text",
      type: "regex",
      pattern: "!\\[.*\\]\\(https?://(?!.*corp\\.example)[^)]*\\?[^)]{40,}\\)",
      stages: ["egress"],
      source: "EchoLeak · CVE-2025-32711",
      reference: "CVE-2025-32711",
      cve: ["CVE-2025-32711"],
      atlas_technique: ["AML.T0057"],
      owasp: ["LLM02"],
    }),
    sig({
      id: "FEED-MCP-0009",
      description: "Flags tool descriptions with hidden orders such as <IMPORTANT> blocks, “do not tell the user” or paths like ~/.ssh.",
      target: "tool_description",
      type: "regex",
      pattern: "(?i)<important>|do not (tell|mention).*user|~/\\.ssh",
      stages: ["mcp_tools_list"],
      source: "MCPTox · MCP-SafetyBench",
      atlas_technique: ["AML.T0051"],
      owasp: ["MCP03"],
    }),
    sig({
      id: "FEED-URL-0031",
      description: "Stops agents calling the Langflow endpoint that allowed unauthenticated code execution.",
      target: "url",
      type: "url_path",
      pattern: "POST */api/v1/validate/code",
      severity: "critical",
      source: "CISA KEV · CVE-2025-3248",
      reference: "CVE-2025-3248",
      cve: ["CVE-2025-3248"],
      atlas_technique: ["AML.T0011"],
      owasp: ["LLM05"],
    }),
    sig({
      id: "FEED-CMD-0102",
      description: "Blocks commands that wipe files or infrastructure, like rm -rf / or terraform destroy.",
      target: "command",
      type: "arg_pattern",
      pattern: "rm -rf / | terraform destroy | aws .* delete",
      severity: "critical",
      source: "Amazon Q wiper prompt",
      atlas_technique: ["AML.T0048"],
      owasp: ["ASI02"],
    }),
  ];
}

/** Rules of the active bundle. `POST /feed/rules` adds to `pendingRules` first; a sync moves them here. */
export const signatures = seeded(seedSignatures);
/** Rules the demo feed server published that the gateway has not loaded yet (`sync_now: false`). */
export const pendingRules = seeded<SeedSignature>(() => []);
/** Version the demo feed server serves (the gateway shows `feedStatus.bundle_version` until it syncs). */
export const feedServer = { bundle_version: 412 };
registerReset(() => {
  feedServer.bundle_version = 412;
});
