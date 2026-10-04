import { describe, expect, it } from "vitest";
import { buildTrace, buildTranscript, events } from "@/mocks/db/events";

const RULE_RE = /^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$/;

describe("Traffic demo data", () => {
  it("has the 12 prototype events plus background traffic, unique ids, valid rule ids, no raw values", () => {
    const ids = events.items.map((e) => e.event_id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(events.items.map((e) => e.seq)).size).toBe(ids.length);
    for (const id of ["tr_8f3a2c", "tr_8f39e1", "tr_9b21e4", "tr_9b1f07", "tr_8f2c90", "tr_8e77a2", "tr_9a0c33", "tr_8d5e10", "tr_8f3a31", "tr_8c9911", "tr_8c7a04", "tr_8b6f55"]) {
      const e = events.items.find((x) => x.trace_id === id);
      expect(e, id).toBeDefined();
      expect(e!.summary.length, id).toBeGreaterThan(20);
      expect(Object.keys(e!.changed_steps).length, id).toBeGreaterThan(0);
    }
    expect(events.items.length).toBeGreaterThan(50);
    for (const e of events.items) {
      for (const r of e.rule_ids) expect(r).toMatch(RULE_RE);
      const trace = buildTrace(e);
      const blob = JSON.stringify([e, trace, e.session_id ? buildTranscript(e.session_id) : null]).replace(/"(prev_)?hash":"[0-9a-f]{64}"/g, "");
      expect(blob).not.toMatch(/\d{11}/); // no PESEL
      expect(blob).not.toMatch(/PL\d{26}/); // no IBAN
      expect(blob).not.toMatch(/bielik|qwen2\.5|qwen3:8b|loan-memo-pl/i);
    }
  });
});
