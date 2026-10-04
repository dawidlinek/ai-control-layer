import { describe, expect, it } from "vitest";
import { api, unwrap } from "@/lib/api/client";

describe("mock API: events", () => {
  it("lists events newest first, with Anna's PESEL + IBAN prompt", async () => {
    const list = unwrap(await api.GET("/admin/v1/events"));
    expect(list.length).toBeGreaterThanOrEqual(3);
    expect(list.map((e) => e.seq)).toEqual([...list.map((e) => e.seq)].sort((a, b) => b - a));
    const anna = list.find((e) => e.trace_id === "tr_8f3a2c")!;
    expect(anna.username).toBe("a.nowak");
    expect(anna.applied).toEqual(["pseudonymise", "route_local"]);
    expect(anna.rule_ids).toEqual(["SEC-PII-01"]);
    expect(anna.session_label?.local_only).toBe(true);
  });

  it("filters by action, rule and subject", async () => {
    const blocks = unwrap(await api.GET("/admin/v1/events", { params: { query: { action: "block" } } }));
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks.every((e) => e.action === "block")).toBe(true);
    const flow = unwrap(await api.GET("/admin/v1/events", { params: { query: { rule_id: "SEC-FLOW-01" } } }));
    expect(flow.map((e) => e.trace_id)).toEqual(["tr_9b21e4"]);
  });

  it("returns a trace with steps and what the model saw (placeholders only)", async () => {
    const trace = unwrap(await api.GET("/admin/v1/events/{event_id}/trace", { params: { path: { event_id: "tr_8f3a2c" } } }));
    expect(trace.steps.map((s) => s.step)).toEqual([
      "identity", "normalise", "rules", "similarity", "classifier", "judge", "decide", "route", "output",
    ]);
    expect(trace.steps.filter((s) => s.changed).map((s) => s.step)).toEqual(["rules", "classifier", "decide", "route"]);
    expect(trace.model_saw).toContain("<PESEL_1>");
    expect(trace.model_saw).not.toMatch(/\d{11}/);
  });

  it("adds an approval step for held requests", async () => {
    const trace = unwrap(await api.GET("/admin/v1/events/{event_id}/trace", { params: { path: { event_id: "tr_9b21e4" } } }));
    expect(trace.steps.map((s) => s.step)).toContain("approval");
  });

  it("serves a session transcript and 404s for unknown ids", async () => {
    const t = unwrap(await api.GET("/admin/v1/sessions/{session_id}/transcript", { params: { path: { session_id: "s_9e21" } } }));
    expect(t.turns.length).toBeGreaterThan(0);
    const missing = await api.GET("/admin/v1/events/{event_id}", { params: { path: { event_id: "nope" } } });
    expect(missing.response.status).toBe(404);
  });
});

describe("mock API: incidents", () => {
  it("has 7 not resolved: 1 high, 2 medium, 4 low", async () => {
    const all = unwrap(await api.GET("/admin/v1/incidents"));
    expect(all).toHaveLength(9);
    const unresolved = all.filter((i) => i.status !== "resolved");
    expect(unresolved).toHaveLength(7);
    const bySeverity = (s: string) => unresolved.filter((i) => i.severity === s).length;
    expect([bySeverity("high"), bySeverity("medium"), bySeverity("low")]).toEqual([1, 2, 4]);
  });

  it("patches status, assignee and adds a note", async () => {
    const updated = unwrap(
      await api.PATCH("/admin/v1/incidents/{incident_id}", {
        params: { path: { incident_id: "inc-0057" } },
        body: { assignee: "k.wojcik", status: "triaged", note: "looking" },
      }),
    );
    expect(updated.assignee).toBe("k.wojcik");
    expect(updated.status).toBe("triaged");
    expect(updated.notes.map((n) => n.text)).toContain("looking");
  });
});

describe("mock API: approvals", () => {
  it("has 3 waiting", async () => {
    const pending = unwrap(await api.GET("/admin/v1/approvals", { params: { query: { status: "pending" } } }));
    expect(pending.map((a) => a.id).sort()).toEqual(["apr-0193", "apr-0194", "apr-0195"]);
    expect(pending.every((a) => new Date(a.expires_at).getTime() > Date.now())).toBe(true);
  });

  it("decides once, with an elevation", async () => {
    const decided = unwrap(
      await api.POST("/admin/v1/approvals/{approval_id}/decision", {
        params: { path: { approval_id: "apr-0193" } },
        body: { decision: "approve", elevation_minutes: 15, note: "checked the remote" },
      }),
    );
    expect(decided.status).toBe("approved");
    expect(decided.elevation?.scope).toBe("tool:opencode.bash");
    const again = await api.POST("/admin/v1/approvals/{approval_id}/decision", {
      params: { path: { approval_id: "apr-0193" } },
      body: { decision: "deny" },
    });
    expect(again.response.status).toBe(409);
  });
});

describe("mock API: users and policy", () => {
  it("finds the signed-in demo user and groups", async () => {
    const u = unwrap(await api.GET("/admin/v1/users/{user_id}", { params: { path: { user_id: "k.wojcik" } } }));
    expect(u.display_name).toBe("Katarzyna Wójcik");
    expect(u.roles).toContain("acl-admin");
    const groups = unwrap(await api.GET("/admin/v1/groups"));
    expect(groups.map((g) => [g.name, g.members])).toEqual([
      ["developers", 14],
      ["credit-analysts", 9],
      ["operations", 12],
      ["security", 6],
    ]);
  });

  it("serves the policy status (live v8 loaded from the file)", async () => {
    const p = unwrap(await api.GET("/admin/v1/policy"));
    expect(p.version).toBe("v8");
    expect(p.locked_controls).toContain("LOCK-01");
  });
});

describe("mock db reset", () => {
  it("restores seed data between tests (the patch above is gone)", async () => {
    const i = unwrap(await api.GET("/admin/v1/incidents/{incident_id}", { params: { path: { incident_id: "inc-0057" } } }));
    expect(i.status).toBe("open");
    expect(i.assignee).toBeNull();
  });
});
