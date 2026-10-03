/** Errors raised by the guard. Messages never contain tokens, arguments or file contents. */

export type GuardErrorCode =
  | "blocked" // gateway said no (action != allow/redact/monitor)
  | "approval_denied"
  | "approval_expired"
  | "approval_timeout"
  | "gateway_unavailable" // network error / timeout / non-2xx
  | "malformed_response"
  | "not_authenticated"
  | "misconfigured"
  | "login_failed";

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  readonly ruleIds: string[];
  readonly decisionId?: string;

  constructor(code: GuardErrorCode, message: string, extra: { ruleIds?: string[]; decisionId?: string } = {}) {
    super(message);
    this.name = "GuardError";
    this.code = code;
    this.ruleIds = extra.ruleIds ?? [];
    this.decisionId = extra.decisionId;
  }
}
