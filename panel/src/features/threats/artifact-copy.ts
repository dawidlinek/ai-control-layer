/**
 * Plain-language copy for model-file scan results. Templates per scanner rule id (deterministic, never LLM-written),
 * with a fallback per verdict so unknown rule ids still read well.
 */
import type { ArtifactScanResult } from "@/lib/api/types";

export type FileResult = "passed" | "blocked" | "suspicious";

export function fileResult(a: ArtifactScanResult): FileResult {
  if (a.verdict === "safe") return "passed";
  if (a.verdict === "suspicious") return "suspicious";
  return "blocked";
}

const RULES: Record<string, { finding: string; about: string }> = {
  "ART-PICKLE-01": {
    finding: "runs code when loaded (pickle)",
    about: "This file would run a shell command the moment someone loads it. Pickle files are blocked by default.",
  },
  "ART-FORMAT-01": {
    finding: "format does not match the file type",
    about:
      "The archive format does not match what this kind of model file should be. A mismatch like this is treated as an attack, not as “could not scan”.",
  },
  "ART-KERAS-01": {
    finding: "Lambda layer runs code",
    about: "The model contains a Lambda layer, which can run arbitrary Python when it is loaded.",
  },
  "ART-GGUF-01": {
    finding: "header and metadata OK",
    about: "A standard GGUF model file. Nothing in it can run code when it is loaded.",
  },
  "ART-ONNX-01": {
    finding: "graph OK, no custom operators",
    about: "A standard ONNX model. It has no custom operators or external data, so loading it cannot run code.",
  },
  "ART-SAFETENSORS-01": {
    finding: "tensors only",
    about: "A safetensors file holds only numbers, never code. The header was checked and is within limits.",
  },
};

/** The finding that explains the result: the first non-info finding, else the first one. */
function mainFinding(a: ArtifactScanResult) {
  return a.findings.find((f) => f.severity !== "info") ?? a.findings[0];
}

export function findingLabel(a: ArtifactScanResult): string {
  const f = mainFinding(a);
  if (!f) return fileResult(a) === "passed" ? "no findings" : "—";
  return RULES[f.rule_id]?.finding ?? f.message.split("\n")[0];
}

export function fileAbout(a: ArtifactScanResult): string {
  const f = mainFinding(a);
  const known = f ? RULES[f.rule_id]?.about : undefined;
  if (known) return known;
  switch (fileResult(a)) {
    case "passed":
      return `The scan found nothing in this ${a.format_detected} file that can run code when it is loaded.`;
    case "suspicious":
      return `The scan found something unusual in this ${a.format_detected} file. It is held until someone checks it.`;
    default:
      return `This ${a.format_detected} file was blocked: loading it could run code or it is not the format it claims to be.`;
  }
}

/** Technical detail (opcode / header), mono. */
export function technicalDetail(a: ArtifactScanResult): string {
  return a.findings.length ? a.findings.map((f) => f.message).join("\n") : `${a.format_detected} · no findings`;
}

/** `3d0a…91c2`. */
export function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  const v = h.replace(/^sha256:/, "");
  return v.length > 12 ? `${v.slice(0, 4)}…${v.slice(-4)}` : v;
}
