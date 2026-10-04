import { describe, expect, it, vi } from "vitest";
import { GuardError } from "../src/errors.js";
import type { ApprovalStatus, DecideRequest, DecideResponse } from "../src/gateway.js";
import { Guard, type GuardGateway } from "../src/guard.js";
import { resolveTool } from "../src/tools.js";
import { testConfig } from "./helpers.js";

const decision = (over: Partial<DecideResponse>): DecideResponse => ({
  decision_id: "dec_42",
  action: "allow",
  rule_ids: [],
  reason: "",
  modified_arguments: null,
  approval: null,
  ...over,
});

function makeGuard(
  decide: (r: DecideRequest) => Promise<DecideResponse>,
  getApproval: (id: string) => Promise<ApprovalStatus> = async () => {
    throw new Error("unexpected poll");
  },
  mcp: string[] = ["files", "core-banking"],
) {
  const gateway: GuardGateway = { decide: vi.fn(decide), getApproval: vi.fn(getApproval) };
  let clock = 0;
  const notify = vi.fn();
  const guard = new Guard({
    cfg: testConfig(),
    gateway,
    directory: "/workspace/demo",
    worktree: "/workspace/demo",
    mcpServers: () => mcp,
    notify,
    sleep: async (ms) => {
      clock += Math.max(ms, 1);
    },
    now: () => clock,
  });
  return { guard, gateway, notify };
}

const call = (tool = "read", args: Record<string, unknown> = { filePath: "/workspace/demo/README.md" }) => ({
  input: { tool, sessionID: "ses_1", callID: "call_1" },
  output: { args },
});

describe("request shape", () => {
  it("sends session, tool id, arguments, call id, cwd, workspace root and client info", async () => {
    const { guard, gateway } = makeGuard(async () => decision({}));
    const { input, output } = call();
    await guard.beforeTool(input, output);
    const sent = (gateway.decide as ReturnType<typeof vi.fn>).mock.calls[0]![0] as DecideRequest;
    expect(sent).toEqual({
      session_id: "ses_1",
      action: {
        kind: "tool_call",
        tool: "opencode.read",
        arguments: { filePath: "/workspace/demo/README.md" },
        tool_call_id: "call_1",
        cwd: "/workspace/demo",
        workspace_root: "/workspace/demo",
      },
      client: { app: "opencode", version: "unknown", device_id: "dev-test-0001" },
    });
  });

  it.each(["read", "write", "edit", "bash", "webfetch", "glob", "grep", "task"])("maps built-in %s", async (name) => {
    const { guard, gateway } = makeGuard(async () => decision({}));
    await guard.beforeTool({ tool: name, sessionID: "s", callID: "c" }, { args: {} });
    const sent = (gateway.decide as ReturnType<typeof vi.fn>).mock.calls[0]![0] as DecideRequest;
    expect(sent.action.tool).toBe(`opencode.${name}`);
    expect(sent.action.server).toBeUndefined();
  });

  it("maps MCP tools to <server>.<tool> with the server field (longest server prefix wins)", () => {
    expect(resolveTool("files_read_file", ["files"])).toEqual({ tool: "files.read_file", server: "files" });
    expect(resolveTool("core-banking_query", ["core", "core-banking"])).toEqual({
      tool: "core-banking.query",
      server: "core-banking",
    });
    expect(resolveTool("rogue_exfil", ["files"])).toEqual({ tool: "opencode.rogue_exfil" });
    expect(resolveTool("files_", ["files"])).toEqual({ tool: "opencode.files_" });
  });
});

describe("outcomes", () => {
  it.each(["allow", "monitor"] as const)("%s lets the call proceed untouched", async (action) => {
    const { guard } = makeGuard(async () => decision({ action }));
    const { input, output } = call();
    await expect(guard.beforeTool(input, output)).resolves.toBeUndefined();
    expect(output.args).toEqual({ filePath: "/workspace/demo/README.md" });
  });

  it("redact rewrites the original args object in place", async () => {
    const { guard } = makeGuard(async () =>
      decision({ action: "redact", rule_ids: ["PII-PESEL"], modified_arguments: { content: "<PESEL_1>" } }),
    );
    const args: Record<string, unknown> = { content: "44051401359", extra: 1 };
    const output = { args };
    await guard.beforeTool({ tool: "write", sessionID: "s", callID: "c" }, output);
    expect(output.args).toBe(args); // OpenCode keeps using its own reference
    expect(args).toEqual({ content: "<PESEL_1>" });
  });

  it("block throws with the rule id, reason and decision id", async () => {
    const { guard } = makeGuard(async () =>
      decision({ action: "block", rule_ids: ["SEC-PATH-01"], reason: "path outside workspace" }),
    );
    const { input, output } = call("read", { filePath: "/home/dev/.ssh/id_rsa" });
    const err = await guard.beforeTool(input, output).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(GuardError);
    const g = err as GuardError;
    expect(g.code).toBe("blocked");
    expect(g.message).toContain("SEC-PATH-01");
    expect(g.message).toContain("path outside workspace");
    expect(g.message).toContain("dec_42");
    expect(g.ruleIds).toEqual(["SEC-PATH-01"]);
    expect(guard.wasBlocked("call_1")).toBe(true);
  });

  it.each(["route_local", "downgrade", "pseudonymise", "sanitize"] as const)(
    "%s is treated as not allowed",
    async (action) => {
      const { guard } = makeGuard(async () => decision({ action, rule_ids: ["X-1"] }));
      const { input, output } = call();
      await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "blocked" });
    },
  );

  it("does not leak argument values into the error", async () => {
    const { guard } = makeGuard(async () => decision({ action: "block", rule_ids: ["SEC-1"], reason: "no" }));
    const { input, output } = call("bash", { command: "echo SECRET-TOKEN-123" });
    const err = (await guard.beforeTool(input, output).catch((e: unknown) => e)) as Error;
    expect(err.message).not.toContain("SECRET-TOKEN-123");
  });
});

describe("approvals", () => {
  const approvalDecision = (scope = "admin") =>
    decision({
      action: "require_approval",
      rule_ids: ["SEC-CONFIRM-01"],
      reason: "bash needs approval",
      approval: { approval_id: "apr_1", status: "pending", approver_scope: scope, expires_at: null },
    });
  const status = (s: ApprovalStatus["status"]): ApprovalStatus => ({
    approval_id: "apr_1",
    status: s,
    rule_ids: ["SEC-CONFIRM-01"],
    reason: "",
  });

  it("polls until approved, then proceeds", async () => {
    const states: ApprovalStatus["status"][] = ["pending", "pending", "approved"];
    const { guard, gateway, notify } = makeGuard(async () => approvalDecision(), async () => status(states.shift()!));
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).resolves.toBeUndefined();
    expect(gateway.getApproval).toHaveBeenCalledTimes(3);
    expect(notify).toHaveBeenCalledWith(
      expect.stringContaining("apr_1"),
      "warning",
      expect.objectContaining({ title: "Approval pending" }),
    );
    expect(notify).toHaveBeenLastCalledWith(expect.stringContaining("approved"), "success", { title: "Approved" });
  });

  it("keeps the pending notice on screen while waiting and links the panel", async () => {
    let clock = 0;
    let polls = 0;
    const notify = vi.fn();
    const guard = new Guard({
      cfg: testConfig({ approvalPollMs: 5_000, approvalTimeoutMs: 600_000, panelUrl: "http://panel.test" }),
      gateway: {
        decide: async () => approvalDecision(),
        getApproval: async () => status(++polls >= 8 ? "approved" : "pending"),
      },
      directory: "/w",
      worktree: "/w",
      mcpServers: () => [],
      notify,
      sleep: async (ms) => {
        clock += ms;
      },
      now: () => clock,
    });
    await guard.beforeTool({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "ls" } });
    const pending = notify.mock.calls.filter((c) => c[1] === "warning");
    expect(pending.length).toBeGreaterThanOrEqual(3); // first notice + reminders every 15 s over 40 s
    expect(pending[0]?.[0]).toContain("http://panel.test/approvals/apr_1");
    expect(pending[0]?.[2]?.durationMs).toBeGreaterThan(15_000);
  });

  it("denied blocks with the rule id", async () => {
    const { guard } = makeGuard(async () => approvalDecision("user"), async () => status("denied"));
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({
      code: "approval_denied",
      message: expect.stringContaining("SEC-CONFIRM-01"),
    });
  });

  it("expired blocks", async () => {
    const { guard } = makeGuard(async () => approvalDecision(), async () => status("expired"));
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "approval_expired" });
  });

  it("times out while pending (bounded wait)", async () => {
    const { guard } = makeGuard(async () => approvalDecision(), async () => status("pending"));
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "approval_timeout" });
  });

  it("honours the approval's own expires_at when it is sooner", async () => {
    const soon = decision({
      action: "require_approval",
      rule_ids: ["SEC-CONFIRM-01"],
      approval: { approval_id: "apr_1", status: "pending", approver_scope: "admin", expires_at: new Date(5).toISOString() },
    });
    const { guard, gateway } = makeGuard(async () => soon, async () => status("pending"));
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "approval_timeout" });
    expect((gateway.getApproval as ReturnType<typeof vi.fn>).mock.calls.length).toBeLessThan(10);
  });

  it("gives up when polling keeps failing (never waits on a dead gateway)", async () => {
    const { guard } = makeGuard(
      async () => approvalDecision(),
      async () => {
        throw new GuardError("gateway_unavailable", "down");
      },
    );
    const { input, output } = call("bash", { command: "ls" });
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "gateway_unavailable" });
  });
});

describe("fail closed", () => {
  it("blocks when the gateway call fails", async () => {
    const { guard } = makeGuard(async () => {
      throw new GuardError("gateway_unavailable", "policy gateway unreachable");
    });
    const { input, output } = call();
    await expect(guard.beforeTool(input, output)).rejects.toMatchObject({ code: "gateway_unavailable" });
    expect(guard.wasBlocked("call_1")).toBe(true);
  });

  it("blocks on any unexpected exception, with a generic message", async () => {
    const { guard } = makeGuard(async () => {
      throw new TypeError("boom: secret");
    });
    const { input, output } = call();
    const err = (await guard.beforeTool(input, output).catch((e: unknown) => e)) as GuardError;
    expect(err).toBeInstanceOf(GuardError);
    expect(err.message).not.toContain("secret");
  });

  it("blocks when redact arrives but the args cannot be rewritten", async () => {
    const { guard } = makeGuard(async () => decision({ action: "redact", modified_arguments: { a: 1 } }));
    await expect(guard.beforeTool({ tool: "write", sessionID: "s", callID: "c" }, { args: undefined })).rejects.toMatchObject({
      code: "malformed_response",
    });
  });
});

describe("MCP session id for the proxy", () => {
  const allow = async () => decision({ action: "allow" });

  it("is the session of the MCP call in flight, and stays the last one afterwards", async () => {
    const { guard } = makeGuard(allow);
    expect(guard.mcpSessionId()).toBeUndefined();
    await guard.beforeTool({ tool: "files_read_file", sessionID: "ses_A", callID: "c1" }, { args: {} });
    expect(guard.mcpSessionId()).toBe("ses_A");
    guard.afterTool({ callID: "c1" });
    expect(guard.mcpSessionId()).toBe("ses_A");
  });

  it("built-in tools do not change it", async () => {
    const { guard } = makeGuard(allow);
    await guard.beforeTool({ tool: "files_read_file", sessionID: "ses_A", callID: "c1" }, { args: {} });
    await guard.beforeTool({ tool: "read", sessionID: "ses_B", callID: "c2" }, { args: {} });
    expect(guard.mcpSessionId()).toBe("ses_A");
  });

  it("is withheld while calls from two sessions are in flight", async () => {
    const { guard } = makeGuard(allow);
    await guard.beforeTool({ tool: "files_read_file", sessionID: "ses_A", callID: "c1" }, { args: {} });
    await guard.beforeTool({ tool: "files_read_file", sessionID: "ses_B", callID: "c2" }, { args: {} });
    expect(guard.mcpSessionId()).toBeUndefined();
    guard.afterTool({ callID: "c1" });
    expect(guard.mcpSessionId()).toBe("ses_B");
  });

  it("a blocked MCP call is not left in flight", async () => {
    const { guard } = makeGuard(async (r) =>
      r.session_id === "ses_A" ? decision({ action: "block", rule_ids: ["SEC-TOOL-01"] }) : decision({ action: "allow" }),
    );
    await expect(
      guard.beforeTool({ tool: "files_read_file", sessionID: "ses_A", callID: "c1" }, { args: {} }),
    ).rejects.toBeInstanceOf(GuardError);
    await guard.beforeTool({ tool: "files_read_file", sessionID: "ses_B", callID: "c2" }, { args: {} });
    expect(guard.mcpSessionId()).toBe("ses_B");
  });
});
