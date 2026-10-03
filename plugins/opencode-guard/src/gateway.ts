/**
 * Gateway client for contracts/decide-api.openapi.yaml. Strict about responses: anything that is not a
 * well-formed 200 is an error, and errors mean "blocked" to the caller (fail closed).
 */
import type { GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";
import type { FetchLike } from "./oidc.js";
import type { TokenManager } from "./tokens.js";

export const ACTIONS = [
  "allow",
  "monitor",
  "redact",
  "pseudonymise",
  "sanitize",
  "route_local",
  "downgrade",
  "require_approval",
  "block",
] as const;
export type DecisionAction = (typeof ACTIONS)[number];

export const APPROVAL_STATUSES = ["pending", "approved", "denied", "expired"] as const;
export type ApprovalState = (typeof APPROVAL_STATUSES)[number];

export interface DecideRequest {
  session_id: string;
  action: {
    kind: "tool_call";
    tool: string;
    arguments: Record<string, unknown>;
    tool_call_id?: string;
    server?: string;
    cwd?: string;
    workspace_root?: string;
  };
  client: { app: string; version?: string; device_id?: string };
}

export interface ApprovalRef {
  approval_id: string;
  status: ApprovalState;
  expires_at?: string | null;
  approver_scope: string;
}

export interface DecideResponse {
  decision_id: string;
  trace_id?: string;
  action: DecisionAction;
  rule_ids: string[];
  reason: string;
  modified_arguments?: Record<string, unknown> | null;
  approval?: ApprovalRef | null;
  policy_version?: string;
}

export interface ApprovalStatus {
  approval_id: string;
  status: ApprovalState;
  rule_ids: string[];
  reason: string;
  expires_at?: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function malformed(what: string): GuardError {
  return new GuardError("malformed_response", `gateway returned a malformed ${what} response`);
}

export function parseDecideResponse(raw: unknown): DecideResponse {
  if (!isObject(raw)) throw malformed("decide");
  const { decision_id, action, rule_ids, reason, modified_arguments, approval } = raw;
  if (typeof decision_id !== "string" || !decision_id) throw malformed("decide");
  if (typeof action !== "string" || !(ACTIONS as readonly string[]).includes(action)) throw malformed("decide");
  const rules = rule_ids === undefined ? [] : rule_ids;
  if (!isStrings(rules)) throw malformed("decide");
  if (reason !== undefined && typeof reason !== "string") throw malformed("decide");
  if (modified_arguments != null && !isObject(modified_arguments)) throw malformed("decide");
  let parsedApproval: ApprovalRef | null = null;
  if (approval != null) {
    if (!isObject(approval) || typeof approval.approval_id !== "string" || !approval.approval_id) throw malformed("decide");
    const status = approval.status ?? "pending";
    if (typeof status !== "string" || !(APPROVAL_STATUSES as readonly string[]).includes(status)) throw malformed("decide");
    parsedApproval = {
      approval_id: approval.approval_id,
      status: status as ApprovalState,
      expires_at: typeof approval.expires_at === "string" ? approval.expires_at : null,
      approver_scope: typeof approval.approver_scope === "string" ? approval.approver_scope : "admin",
    };
  }
  if (action === "require_approval" && !parsedApproval) throw malformed("decide");
  if (action === "redact" && !isObject(modified_arguments)) throw malformed("decide");
  return {
    decision_id,
    trace_id: typeof raw.trace_id === "string" ? raw.trace_id : undefined,
    action: action as DecisionAction,
    rule_ids: rules,
    reason: typeof reason === "string" ? reason : "",
    modified_arguments: (modified_arguments as Record<string, unknown> | null | undefined) ?? null,
    approval: parsedApproval,
    policy_version: typeof raw.policy_version === "string" ? raw.policy_version : undefined,
  };
}

export function parseApprovalStatus(raw: unknown): ApprovalStatus {
  if (!isObject(raw)) throw malformed("approval");
  const { approval_id, status, rule_ids, reason } = raw;
  if (typeof approval_id !== "string" || typeof status !== "string") throw malformed("approval");
  if (!(APPROVAL_STATUSES as readonly string[]).includes(status)) throw malformed("approval");
  const rules = rule_ids === undefined ? [] : rule_ids;
  if (!isStrings(rules)) throw malformed("approval");
  return {
    approval_id,
    status: status as ApprovalState,
    rule_ids: rules,
    reason: typeof reason === "string" ? reason : "",
    expires_at: typeof raw.expires_at === "string" ? raw.expires_at : null,
  };
}

export class GatewayClient {
  constructor(
    private readonly cfg: GuardConfig,
    private readonly tokens: TokenManager,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  private async call(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
    if (this.cfg.problems.length > 0) {
      throw new GuardError("misconfigured", `guard misconfigured: ${this.cfg.problems.join("; ")}`);
    }
    const token = await this.tokens.requireAccessToken();
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.cfg.gatewayUrl}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/json",
          "x-device-id": this.cfg.deviceId,
          "x-client-app": this.cfg.clientApp,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.cfg.requestTimeoutMs),
      });
    } catch (err) {
      throw new GuardError("gateway_unavailable", `policy gateway unreachable (${(err as Error).name}); action blocked`);
    }
    if (res.status !== 200) {
      throw new GuardError("gateway_unavailable", `policy gateway answered HTTP ${res.status}; action blocked`);
    }
    try {
      return await res.json();
    } catch {
      throw malformed("JSON");
    }
  }

  async decide(request: DecideRequest): Promise<DecideResponse> {
    return parseDecideResponse(await this.call("POST", "/v1/decide", request));
  }

  async getApproval(id: string): Promise<ApprovalStatus> {
    return parseApprovalStatus(await this.call("GET", `/v1/approvals/${encodeURIComponent(id)}`));
  }

  /** User-scope approvals only (`approver_scope == "user"`). Used by a human-facing UI, never by the agent. */
  async decideApproval(id: string, decision: "approve" | "deny", note?: string): Promise<ApprovalStatus> {
    return parseApprovalStatus(
      await this.call("POST", `/v1/approvals/${encodeURIComponent(id)}/decision`, { decision, ...(note ? { note } : {}) }),
    );
  }
}
