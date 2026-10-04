import { describe, expect, it } from "vitest";
import { makeEvent } from "@/mocks/db/events";
import { clientLine, matchesFilters, modelOrTool, riskLabel, serverParams, sessionLabelText, splitPlaceholders, type TrafficFilters } from "./model";

const base: TrafficFilters = { range: "24h", decision: [], who: null, point: [], group: null, dataClass: [], q: "", hideAllowed: false };
const ev = (over: Parameters<typeof makeEvent>[0] extends infer P ? Partial<P> : never = {}) =>
  makeEvent({ event_id: "evt_1", seq: 1, timestamp: new Date().toISOString(), ...over });

describe("traffic model", () => {
  it("shows the model, else the tool_preview, else the bare tool", () => {
    expect(modelOrTool(ev({ model: "gemini/flash", tool_preview: "x" }))).toBe("gemini/flash");
    expect(modelOrTool(ev({ tool: "bash", tool_preview: "bash: git push origin main" }))).toBe("bash: git push origin main");
    expect(modelOrTool(ev({ tool: "bash" }))).toBe("bash");
    expect(modelOrTool(ev())).toBe("—");
  });

  it("splits placeholders, secrets and removed sentences into chips", () => {
    expect(splitPlaceholders("client <PERSON_1>, key ‹SECRET:api_key› … [removed: instruction] end")).toEqual([
      { text: "client ", placeholder: false },
      { text: "<PERSON_1>", placeholder: true },
      { text: ", key ", placeholder: false },
      { text: "‹SECRET:api_key›", placeholder: true },
      { text: " … ", placeholder: false },
      { text: "[removed: instruction]", placeholder: true },
      { text: " end", placeholder: false },
    ]);
    expect(splitPlaceholders("a < b and c > d")).toEqual([{ text: "a < b and c > d", placeholder: false }]);
  });

  it("sends supported filters to the server and keeps the rest client-side", () => {
    expect(serverParams({ ...base, decision: ["block"], point: ["tool_call", "ingress"], q: "SEC-FLOW-01", who: "j.kowalski" })).toEqual({
      range: "24h", subject: "j.kowalski", group: undefined, action: "block", point: undefined, rule_id: "SEC-FLOW-01",
    });
    const allow = ev({ action: "allow", applied: ["allow"], point: "ingress" });
    expect(matchesFilters(allow, { ...base, hideAllowed: true })).toBe(false);
    expect(matchesFilters(allow, { ...base, point: ["tool_call", "egress"] })).toBe(false);
    expect(matchesFilters(allow, { ...base, decision: ["allow", "block"] })).toBe(true);
    expect(matchesFilters(ev({ username: "a.nowak" }), { ...base, q: "anna" }, () => "Anna Nowak")).toBe(true);
  });

  it("formats risk, client and the session label", () => {
    expect(riskLabel(0.31)).toBe("0.31 · low");
    expect(riskLabel(0.52)).toBe("0.52 · medium");
    expect(riskLabel(0.78)).toBe("0.78 · high");
    expect(riskLabel(null)).toBe("—");
    expect(clientLine(ev({ client_app: "librechat", groups: ["credit-analysts"] }))).toBe("LibreChat · credit-analysts");
    expect(clientLine(ev({ client_app: "agent", agent_id: "research-bot", session_id: "s_77c1" }))).toBe("agent · session s_77c1");
    const since = new Date(2026, 9, 3, 14, 3, 12).toISOString();
    expect(sessionLabelText({ data_class: "confidential", trust: "trusted", since, local_only: true })).toBe(
      "Session confidential since 14:03 · local only",
    );
  });
});
