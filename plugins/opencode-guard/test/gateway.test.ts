import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GatewayClient, parseDecideResponse } from "../src/gateway.js";
import { TokenManager } from "../src/tokens.js";
import { DECIDE_OK, json, startServer, testConfig, type TestServer } from "./helpers.js";

let srv: TestServer;
beforeEach(async () => {
  srv = await startServer((_r, res) => json(res, 200, DECIDE_OK));
});
afterEach(async () => {
  await srv.close();
});

function client(over: Record<string, unknown> = {}, loggedIn = true) {
  const cfg = testConfig({ gatewayUrl: srv.url, requestTimeoutMs: 500, ...over });
  const tokens = new TokenManager(cfg, {});
  if (loggedIn) tokens.set({ access: "tok-abc", refresh: "r", expires: Date.now() + 600_000 });
  return new GatewayClient(cfg, tokens);
}

const request = {
  session_id: "s",
  action: { kind: "tool_call" as const, tool: "opencode.read", arguments: {} },
  client: { app: "opencode" },
};

describe("GatewayClient", () => {
  it("POSTs /v1/decide with bearer token and attribution headers", async () => {
    await client().decide(request);
    const r = srv.requests[0]!;
    expect(r.method).toBe("POST");
    expect(r.url).toBe("/v1/decide");
    expect(r.headers.authorization).toBe("Bearer tok-abc");
    expect(r.headers["x-device-id"]).toBe("dev-test-0001");
    expect(r.headers["x-client-app"]).toBe("opencode");
    expect(JSON.parse(r.body)).toEqual(request);
  });

  it.each([401, 403, 422, 500, 501])("non-200 (%i) is an error", async (status) => {
    srv.setHandler((_r, res) => json(res, status, { detail: "x" }));
    await expect(client().decide(request)).rejects.toMatchObject({ code: "gateway_unavailable" });
  });

  it("network failure is an error", async () => {
    const c = client({ gatewayUrl: "http://127.0.0.1:1" });
    await expect(c.decide(request)).rejects.toMatchObject({ code: "gateway_unavailable" });
  });

  it("timeout is an error", async () => {
    srv.setHandler(() => undefined); // never answers
    await expect(client({ requestTimeoutMs: 50 }).decide(request)).rejects.toMatchObject({ code: "gateway_unavailable" });
  });

  it("non-JSON 200 is malformed", async () => {
    srv.setHandler((_r, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html>proxy error</html>");
    });
    await expect(client().decide(request)).rejects.toMatchObject({ code: "malformed_response" });
  });

  it.each([
    ["missing decision_id", { action: "allow" }],
    ["unknown action", { decision_id: "d", action: "maybe" }],
    ["rule_ids not strings", { decision_id: "d", action: "block", rule_ids: [1] }],
    ["redact without modified_arguments", { decision_id: "d", action: "redact" }],
    ["require_approval without approval", { decision_id: "d", action: "require_approval" }],
    ["array body", [1, 2]],
  ])("malformed: %s", async (_name, body) => {
    srv.setHandler((_r, res) => json(res, 200, body));
    await expect(client().decide(request)).rejects.toMatchObject({ code: "malformed_response" });
  });

  it("not logged in -> not_authenticated, nothing is sent", async () => {
    await expect(client({}, false).decide(request)).rejects.toMatchObject({ code: "not_authenticated" });
    expect(srv.requests).toHaveLength(0);
  });

  it("misconfiguration blocks without sending", async () => {
    const cfg = testConfig({ gatewayUrl: "" });
    const c = new GatewayClient(cfg, new TokenManager(cfg, {}));
    await expect(c.decide(request)).rejects.toMatchObject({ code: "misconfigured" });
  });

  it("getApproval / decideApproval hit the documented paths", async () => {
    srv.setHandler((_r, res) => json(res, 200, { approval_id: "a/1", status: "approved", rule_ids: ["SEC-X-1"] }));
    const c = client();
    expect((await c.getApproval("a/1")).status).toBe("approved");
    await c.decideApproval("a/1", "deny", "no");
    expect(srv.requests[0]!.method + " " + srv.requests[0]!.url).toBe("GET /v1/approvals/a%2F1");
    expect(srv.requests[1]!.method + " " + srv.requests[1]!.url).toBe("POST /v1/approvals/a%2F1/decision");
    expect(JSON.parse(srv.requests[1]!.body)).toEqual({ decision: "deny", note: "no" });
  });
});

describe("parseDecideResponse", () => {
  it("accepts a full response", () => {
    const parsed = parseDecideResponse({
      decision_id: "d",
      trace_id: "t",
      action: "require_approval",
      rule_ids: ["SEC-A-1"],
      reason: "r",
      approval: { approval_id: "a", status: "pending", approver_scope: "user", expires_at: "2030-01-01T00:00:00Z" },
      policy_version: "v",
    });
    expect(parsed.approval?.approver_scope).toBe("user");
  });
});
