/**
 * Known-threat signatures shown on the Signatures tab.
 *
 * The admin API has no endpoint that lists the signatures of the active bundle (`FeedStatus` only carries version,
 * entry count, verification and sync times, and has no free-form map), so this is a typed, curated demo list of the
 * seed bundle's headline rules (FeedArtifacts prototype + HANDOFF section 6). Hits are counted from real traffic events.
 */
import type { Decision, Severity } from "@/lib/decisions";

export type LooksAt = "package" | "answer text" | "tool description" | "URL in a tool call" | "shell command";

export interface Signature {
  id: string;
  what: string;
  source: string;
  looksAt: LooksAt;
  action: Decision;
  about: string;
  pattern: string;
  severity: Severity;
  tags: string;
  expires: string;
}

export const SIGNATURES: readonly Signature[] = [
  {
    id: "FEED-PKG-0007",
    what: "litellm 1.82.7 and 1.82.8 — backdoored PyPI releases",
    source: "OSV · March 2026",
    looksAt: "package",
    action: "block",
    about: "Blocks installing the two litellm releases that were published with a backdoor.",
    pattern: "pypi: litellm == 1.82.7 | 1.82.8",
    severity: "critical",
    tags: "AML.T0010 · LLM03",
    expires: "never",
  },
  {
    id: "FEED-PKG-0012",
    what: "look-alike names of popular AI packages",
    source: "internal list",
    looksAt: "package",
    action: "block",
    about: "Blocks typosquatted packages such as “openal” or “langchian”.",
    pattern: "pypi|npm: openal, langchian, transformerss, …",
    severity: "medium",
    tags: "AML.T0010 · LLM03",
    expires: "never",
  },
  {
    id: "FEED-PKG-0142",
    what: "torchtriton — dependency-confusion package",
    source: "OSV · PyTorch advisory",
    looksAt: "package",
    action: "block",
    about: "Blocks installing the fake torchtriton package used in a dependency-confusion attack.",
    pattern: "pypi: torchtriton (any version)",
    severity: "critical",
    tags: "AML.T0010 · LLM03",
    expires: "never",
  },
  {
    id: "FEED-EXF-0044",
    what: "images and links that carry data in the URL",
    source: "EchoLeak · CVE-2025-32711",
    looksAt: "answer text",
    action: "block",
    about: "Removes markdown images and links whose address carries encoded data to an outside site.",
    pattern: "!\\[.*\\]\\(https?://(?!.*corp\\.example)[^)]*\\?[^)]{40,}\\)",
    severity: "high",
    tags: "AML.T0057 · LLM02",
    expires: "never",
  },
  {
    id: "FEED-MCP-0009",
    what: "hidden instructions in MCP tool descriptions",
    source: "MCPTox · MCP-SafetyBench",
    looksAt: "tool description",
    action: "block",
    about: "Flags tool descriptions with hidden orders such as <IMPORTANT> blocks, “do not tell the user” or paths like ~/.ssh.",
    pattern: "(?i)<important>|do not (tell|mention).*user|~/\\.ssh",
    severity: "high",
    tags: "AML.T0051 · MCP03",
    expires: "never",
  },
  {
    id: "FEED-URL-0031",
    what: "Langflow code-validation endpoint",
    source: "CISA KEV · CVE-2025-3248",
    looksAt: "URL in a tool call",
    action: "block",
    about: "Stops agents calling the Langflow endpoint that allowed unauthenticated code execution.",
    pattern: "POST */api/v1/validate/code",
    severity: "critical",
    tags: "AML.T0011 · LLM05",
    expires: "never",
  },
  {
    id: "FEED-CMD-0102",
    what: "destructive shell commands",
    source: "Amazon Q wiper prompt",
    looksAt: "shell command",
    action: "block",
    about: "Blocks commands that wipe files or infrastructure, like rm -rf / or terraform destroy.",
    pattern: "rm -rf / | terraform destroy | aws .* delete",
    severity: "critical",
    tags: "AML.T0048 · ASI02",
    expires: "never",
  },
];
