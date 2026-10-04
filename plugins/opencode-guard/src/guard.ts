/** The `tool.execute.before` decision logic. Pure of OpenCode types so it can be unit-tested directly. */
import type { GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";
import type { ApprovalRef, ApprovalStatus, DecideRequest, DecideResponse } from "./gateway.js";
import { replaceArgsInPlace, resolveTool } from "./tools.js";

export interface GuardGateway {
  decide(request: DecideRequest): Promise<DecideResponse>;
  getApproval(id: string): Promise<ApprovalStatus>;
}

export interface GuardDeps {
  cfg: GuardConfig;
  gateway: GuardGateway;
  /** Project directory (cwd of the tool) and git worktree root as reported by OpenCode. */
  directory: string;
  worktree: string;
  /** Governed MCP servers (names as configured in OpenCode). */
  mcpServers: () => Iterable<string>;
  notify?: (message: string, variant: NotifyVariant, options?: NotifyOptions) => void;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export type NotifyVariant = "info" | "success" | "warning" | "error";
export interface NotifyOptions {
  /** Toast title in the TUI. */
  title?: string;
  /** How long the TUI keeps the toast (ms). */
  durationMs?: number;
}

/** Re-show the "approval pending" toast this often while waiting, so it stays on screen in the TUI. */
export const APPROVAL_REMINDER_MS = 15_000;

export interface ToolInput {
  tool: string;
  sessionID: string;
  callID: string;
}

const MAX_REMEMBERED_BLOCKS = 1000;

function clip(text: string, max = 500): string {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function blockedMessage(tool: string, response: Pick<DecideResponse, "rule_ids" | "reason" | "decision_id">): string {
  const rules = response.rule_ids.length > 0 ? response.rule_ids.join(", ") : "no-rule-id";
  const why = response.reason ? `: ${clip(response.reason)}` : "";
  return `Blocked by company policy [${rules}] for ${tool}${why} (decision ${response.decision_id})`;
}

export class Guard {
  private readonly blocked = new Set<string>();
  /** MCP calls between `tool.execute.before` and `tool.execute.after`: callID -> OpenCode session id. */
  private readonly pendingMcp = new Map<string, string>();
  private lastMcpSession: string | undefined;

  constructor(private readonly deps: GuardDeps) {}

  /** True when the gateway refused this tool call (used by the `permission.ask` hook as defence in depth). */
  wasBlocked(callID: string): boolean {
    return this.blocked.has(callID);
  }

  private remember(callID: string): void {
    if (this.blocked.size >= MAX_REMEMBERED_BLOCKS) {
      const oldest = this.blocked.values().next().value;
      if (oldest !== undefined) this.blocked.delete(oldest);
    }
    this.blocked.add(callID);
  }

  /**
   * OpenCode session id for the gateway's MCP proxy (`X-Session-Id`), so chat, /v1/decide and MCP share one
   * information-flow session. MCP transports are per server, not per session: the value is the session of the
   * MCP call in flight. With calls from two sessions in flight at once there is no right answer, so none is sent
   * and the proxy falls back to the principal-wide MCP session (taint still accumulates there).
   */
  mcpSessionId(): string | undefined {
    const inFlight = new Set(this.pendingMcp.values());
    if (inFlight.size > 1) return undefined;
    if (inFlight.size === 1) return inFlight.values().next().value;
    return this.lastMcpSession;
  }

  /** `tool.execute.after`: the call is finished. */
  afterTool(input: Pick<ToolInput, "callID">): void {
    this.pendingMcp.delete(input.callID);
  }

  /** Throws to block. Returns normally for allow / monitor / redact (args rewritten in place) / approved. */
  async beforeTool(input: ToolInput, output: { args: unknown }): Promise<void> {
    try {
      await this.check(input, output);
    } catch (err) {
      this.pendingMcp.delete(input.callID);
      this.remember(input.callID);
      if (err instanceof GuardError) throw err;
      // Any unexpected failure also blocks; the message stays generic so nothing sensitive leaks.
      throw new GuardError("gateway_unavailable", "guard failure; action blocked");
    }
  }

  private async check(input: ToolInput, output: { args: unknown }): Promise<void> {
    const { cfg, gateway } = this.deps;
    const resolved = resolveTool(input.tool, this.deps.mcpServers());
    if (resolved.server) {
      this.pendingMcp.set(input.callID, input.sessionID);
      this.lastMcpSession = input.sessionID;
    }
    const args =
      output.args && typeof output.args === "object" && !Array.isArray(output.args)
        ? (output.args as Record<string, unknown>)
        : {};
    const request: DecideRequest = {
      session_id: input.sessionID,
      action: {
        kind: "tool_call",
        tool: resolved.tool,
        arguments: args,
        tool_call_id: input.callID,
        ...(resolved.server ? { server: resolved.server } : {}),
        cwd: this.deps.directory,
        workspace_root: this.deps.worktree,
      },
      client: { app: cfg.clientApp, version: cfg.clientVersion, device_id: cfg.deviceId },
    };
    const decision = await gateway.decide(request);

    switch (decision.action) {
      case "allow":
      case "monitor":
        return;
      case "redact":
        replaceArgsInPlace(output.args, decision.modified_arguments ?? {});
        return;
      case "require_approval":
        await this.awaitApproval(resolved.tool, decision);
        this.deps.notify?.(
          `${resolved.tool} approved; it runs once (approval ${decision.approval?.approval_id})`,
          "success",
          { title: "Approved" },
        );
        return;
      default:
        // block, route_local, downgrade, pseudonymise, sanitize: the contract says "not allowed".
        throw new GuardError("blocked", blockedMessage(resolved.tool, decision), {
          ruleIds: decision.rule_ids,
          decisionId: decision.decision_id,
        });
    }
  }

  private async awaitApproval(tool: string, decision: DecideResponse): Promise<void> {
    const { cfg, gateway } = this.deps;
    const ref = decision.approval as ApprovalRef;
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const now = this.deps.now ?? Date.now;
    const extra = { ruleIds: decision.rule_ids, decisionId: decision.decision_id };

    const expires = ref.expires_at ? Date.parse(ref.expires_at) : Number.NaN;
    const deadline = Math.min(now() + cfg.approvalTimeoutMs, Number.isFinite(expires) ? expires : Infinity);
    const who = ref.approver_scope === "user" ? "the approver for your account" : "an administrator";
    const rules = decision.rule_ids.join(", ") || "no-rule-id";
    const where = cfg.panelUrl ? ` Decide in ${cfg.panelUrl}/approvals/${encodeURIComponent(ref.approval_id)}` : "";
    const pending = () =>
      this.deps.notify?.(
        `${tool} is waiting for approval from ${who} [${rules}] (approval ${ref.approval_id}).${where}`,
        "warning",
        { title: "Approval pending", durationMs: APPROVAL_REMINDER_MS + 2_000 },
      );
    pending();
    let lastReminder = now();

    let status = ref.status;
    let failures = 0;
    for (;;) {
      if (status === "approved") return;
      if (status === "denied") {
        throw new GuardError("approval_denied", `Approval denied [${decision.rule_ids.join(", ") || "no-rule-id"}] for ${tool} (approval ${ref.approval_id})`, extra);
      }
      if (status === "expired") {
        throw new GuardError("approval_expired", `Approval expired [${decision.rule_ids.join(", ") || "no-rule-id"}] for ${tool} (approval ${ref.approval_id})`, extra);
      }
      if (now() >= deadline) {
        throw new GuardError("approval_timeout", `Approval timed out [${decision.rule_ids.join(", ") || "no-rule-id"}] for ${tool} (approval ${ref.approval_id})`, extra);
      }
      await sleep(Math.min(cfg.approvalPollMs, Math.max(0, deadline - now())));
      if (now() - lastReminder >= APPROVAL_REMINDER_MS) {
        pending();
        lastReminder = now();
      }
      try {
        status = (await gateway.getApproval(ref.approval_id)).status;
        failures = 0;
      } catch (err) {
        // Tolerate a short outage while polling, but never wait for approval on a dead gateway.
        if (++failures >= 3) throw err;
      }
    }
  }
}
