"use client";

import { SidebarSection } from "@/components/rogatka";
import { formatNumber } from "@/lib/format";
import type { ModelInfo } from "@/lib/api/types";
import { usageText } from "./details";

interface GuardRow {
  role: string;
  model: string;
  usedFor: string;
  today: string;
}

/**
 * Supporting ("guard") models, read-only (HANDOFF section 7.1). The classifier and NER run inside the gateway and are
 * not in `/admin/v1/models`, so they are described here; embeddings and judge come from the API when it lists them.
 */
const STATIC: GuardRow[] = [
  {
    role: "Injection classifier",
    model: "DeBERTa injection model · ONNX on CPU",
    usedFor: "injection score for every prompt and tool result",
    today: "—",
  },
  {
    role: "PII NER",
    model: "Presidio + GLiNER PII model · CPU",
    usedFor: "names and other personal data the validators cannot find",
    today: "—",
  },
];

function fromApi(models: readonly ModelInfo[], kind: "embeddings" | "judge"): GuardRow {
  const m = models.find((x) => (x.tags.guard ?? (x.role ?? "").toLowerCase()).startsWith(kind === "judge" ? "judge" : "embedding"));
  const fallback =
    kind === "judge"
      ? { role: "Judge", model: "local Qwen ~27B with judge prompts", usedFor: "uncertain or risky requests only (about 5–6 %)" }
      : { role: "Embeddings", model: "bge-m3 · local only", usedFor: "similarity to known attacks, Automation Insights" };
  if (!m) return { ...fallback, today: "—" };
  return {
    role: fallback.role,
    model: m.id,
    usedFor: m.tags.about ?? fallback.usedFor,
    today: `${formatNumber(m.requests_day)} req · ${usageText(m)}`,
  };
}

export function GuardModels({ models }: { models: readonly ModelInfo[] }) {
  const rows = [...STATIC, fromApi(models, "embeddings"), fromApi(models, "judge")];
  return (
    <div className="rounded-[8px] border border-border bg-surface">
      <SidebarSection title="Guard models" aside="read-only · they can only make a decision stricter" className="border-b-0 pb-1">
        <div className="rg-scroll overflow-x-auto">
          <table aria-label="Guard models" className="w-full min-w-[620px] border-separate border-spacing-0 text-[12.5px]">
            <thead>
              <tr className="text-left text-[10.5px] font-semibold uppercase tracking-[.05em] text-muted">
                <th scope="col" className="py-1.5 pr-3 font-semibold">Guard</th>
                <th scope="col" className="py-1.5 pr-3 font-semibold">Model</th>
                <th scope="col" className="py-1.5 pr-3 font-semibold">Used for</th>
                <th scope="col" className="py-1.5 text-right font-semibold">Today</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.role}>
                  <td className="border-t border-border py-2 pr-3 font-medium">{r.role}</td>
                  <td className="border-t border-border py-2 pr-3 font-mono text-[12px]">{r.model}</td>
                  <td className="border-t border-border py-2 pr-3 text-muted">{r.usedFor}</td>
                  <td className="border-t border-border py-2 text-right font-mono text-[12px]">{r.today}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SidebarSection>
    </div>
  );
}
