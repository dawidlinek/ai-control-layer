/** Hook builders that do not depend on OpenCode runtime types (so they can be tested with plain objects). */
import type { GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";
import type { TokenManager } from "./tokens.js";

/** Headers added to every LLM request made through the company provider. */
export async function buildChatHeaders(
  cfg: GuardConfig,
  tokens: TokenManager,
  input: { sessionID: string; model: { providerID: string } },
): Promise<Record<string, string>> {
  // Never attach company credentials to some other provider's requests.
  if (input.model.providerID !== cfg.providerId) return {};
  const headers: Record<string, string> = {
    "X-Device-Id": cfg.deviceId,
    "X-Client-App": cfg.clientApp,
    "X-Client-Version": cfg.clientVersion,
    "X-Session-Id": input.sessionID,
  };
  const token = await tokens.accessToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function toHeaders(init?: RequestInit): Headers {
  const headers = new Headers();
  const source = init?.headers;
  if (!source) return headers;
  if (source instanceof Headers) source.forEach((v, k) => headers.set(k, v));
  else if (Array.isArray(source)) for (const [k, v] of source) headers.set(k, String(v));
  else for (const [k, v] of Object.entries(source)) if (v !== undefined) headers.set(k, String(v));
  return headers;
}

/**
 * Provider-level fetch installed by the auth loader: refreshes the token when needed and sets Authorization.
 * Only requests to the gateway origin get the token; anything else is refused (fail closed).
 */
export function makeGuardedFetch(
  cfg: GuardConfig,
  tokens: TokenManager,
  fetchImpl: (input: string | URL | Request, init?: RequestInit) => Promise<Response> = fetch,
) {
  return async (request: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = request instanceof Request ? request.url : request.toString();
    if (cfg.problems.length > 0 || new URL(url).origin !== new URL(cfg.gatewayUrl).origin) {
      throw new GuardError("misconfigured", "model requests may only go to the company gateway");
    }
    const headers = toHeaders(init ?? (request instanceof Request ? { headers: request.headers } : undefined));
    headers.set("authorization", `Bearer ${await tokens.requireAccessToken()}`);
    return fetchImpl(request, { ...init, headers });
  };
}
