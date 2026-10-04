/** OWASP LLM Top 10 (2025), OWASP Agentic (ASI) and MCP names for the "Top risks" list. */
export const RISK_NAMES: Record<string, string> = {
  LLM01: "Prompt injection",
  LLM02: "Sensitive information disclosure",
  LLM03: "Supply chain",
  LLM04: "Data and model poisoning",
  LLM05: "Improper output handling",
  LLM06: "Excessive agency",
  LLM07: "System prompt leakage",
  LLM08: "Vector and embedding weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded consumption",
  ASI01: "Agent goal hijack",
  ASI02: "Tool misuse",
  ASI03: "Identity and privilege abuse",
  ASI04: "Agentic supply chain",
  ASI05: "Unexpected code execution",
  ASI06: "Memory and context poisoning",
  ASI07: "Insecure inter-agent communication",
  ASI08: "Cascading failures",
  ASI09: "Human-agent trust exploitation",
  ASI10: "Rogue agents",
  MCP: "Tool poisoning (rug pull)",
};

export interface Risk {
  /** Short id, e.g. "LLM02" (the gateway sends "LLM02:2025"). */
  id: string;
  /** Human name; the lookup name, or the id when nothing better is known. */
  name: string;
  /** The raw taxonomy key(s) merged into this row (used for the Traffic search link). */
  count: number;
}

/** "LLM02:2025" -> "LLM02"; "owasp_llm:LLM02:2025" -> "LLM02"; anything else is returned as is. */
export function shortRiskId(raw: string): string {
  const m = /(?:^|[:\s/])((?:LLM|ASI)\d{2})(?::\d{4})?$/i.exec(raw.trim());
  if (m) return m[1]!.toUpperCase();
  return raw.trim().replace(/:\d{4}$/, "");
}

/** `top_taxonomy` (tag -> count) as sorted rows with a short id and a name; ids that differ only by year are merged. */
export function topRisks(taxonomy: Record<string, number>, limit = 5): Risk[] {
  const merged = new Map<string, number>();
  for (const [raw, n] of Object.entries(taxonomy)) {
    const id = shortRiskId(raw);
    merged.set(id, (merged.get(id) ?? 0) + n);
  }
  return [...merged.entries()]
    .map(([id, count]) => ({ id, name: RISK_NAMES[id] ?? id, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}
