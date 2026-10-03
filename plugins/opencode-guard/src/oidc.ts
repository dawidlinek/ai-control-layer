/** Keycloak OAuth 2.0 device authorization grant (RFC 8628) and refresh-token grant. Public client, no secret. */
import type { GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface TokenSet {
  access: string;
  refresh: string;
  /** Epoch milliseconds at which `access` expires. */
  expires: number;
}

export interface DeviceAuthorization {
  deviceCode: string;
  userCode: string;
  /** URL to show the user (the "complete" variant already embeds the code when Keycloak provides it). */
  verificationUrl: string;
  verificationUrlPlain: string;
  intervalMs: number;
  expiresAt: number;
}

const GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code";

function endpoints(cfg: GuardConfig) {
  const base = `${cfg.oidcBaseUrl}/protocol/openid-connect`;
  return { device: `${base}/auth/device`, token: `${base}/token` };
}

/** Keycloak builds verification URLs from the request host; show the browser-reachable issuer origin instead. */
export function browserUrl(cfg: GuardConfig, url: string): string {
  try {
    const u = new URL(url);
    const back = new URL(cfg.oidcBaseUrl);
    const front = new URL(cfg.issuer);
    if (u.origin === back.origin && back.origin !== front.origin) {
      return `${front.origin}${u.pathname}${u.search}`;
    }
  } catch {
    /* fall through */
  }
  return url;
}

async function postForm(
  fetchImpl: FetchLike,
  url: string,
  form: Record<string, string>,
  timeoutMs: number,
): Promise<{ status: number; body: Record<string, unknown> }> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams(form).toString(),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new GuardError("login_failed", `identity provider unreachable (${(err as Error).name})`);
  }
  let body: Record<string, unknown> = {};
  try {
    const parsed: unknown = await res.json();
    if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
  } catch {
    /* non-JSON error page: leave body empty */
  }
  return { status: res.status, body };
}

export async function startDeviceFlow(
  cfg: GuardConfig,
  fetchImpl: FetchLike = fetch,
  now: () => number = Date.now,
): Promise<DeviceAuthorization> {
  const { status, body } = await postForm(
    fetchImpl,
    endpoints(cfg).device,
    { client_id: cfg.clientId, scope: cfg.scope },
    cfg.requestTimeoutMs,
  );
  const deviceCode = body.device_code;
  const userCode = body.user_code;
  const plain = body.verification_uri;
  if (status !== 200 || typeof deviceCode !== "string" || typeof userCode !== "string" || typeof plain !== "string") {
    throw new GuardError("login_failed", `device authorization failed (HTTP ${status})`);
  }
  const complete = typeof body.verification_uri_complete === "string" ? body.verification_uri_complete : plain;
  const interval = typeof body.interval === "number" && body.interval > 0 ? body.interval : 5;
  const expiresIn = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 600;
  return {
    deviceCode,
    userCode,
    verificationUrl: browserUrl(cfg, complete),
    verificationUrlPlain: browserUrl(cfg, plain),
    intervalMs: interval * 1000,
    expiresAt: now() + expiresIn * 1000,
  };
}

function tokenSetFrom(body: Record<string, unknown>, now: number): TokenSet {
  const access = body.access_token;
  const refresh = body.refresh_token;
  const expiresIn = typeof body.expires_in === "number" ? body.expires_in : 300;
  if (typeof access !== "string" || typeof refresh !== "string") {
    throw new GuardError("login_failed", "identity provider returned an incomplete token response");
  }
  return { access, refresh, expires: now + expiresIn * 1000 };
}

/** Polls the token endpoint until the user approves, denies or the code expires. */
export async function pollDeviceToken(
  cfg: GuardConfig,
  device: DeviceAuthorization,
  deps: { fetch?: FetchLike; sleep?: (ms: number) => Promise<void>; now?: () => number } = {},
): Promise<TokenSet> {
  const fetchImpl = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = deps.now ?? Date.now;
  let interval = device.intervalMs;
  for (;;) {
    if (now() >= device.expiresAt) throw new GuardError("login_failed", "the login code expired; start again");
    await sleep(interval);
    const { status, body } = await postForm(
      fetchImpl,
      endpoints(cfg).token,
      { grant_type: GRANT_DEVICE, device_code: device.deviceCode, client_id: cfg.clientId },
      cfg.requestTimeoutMs,
    );
    if (status === 200) return tokenSetFrom(body, now());
    const error = typeof body.error === "string" ? body.error : "";
    if (error === "authorization_pending") continue;
    if (error === "slow_down") {
      interval += 5_000;
      continue;
    }
    if (error === "access_denied") throw new GuardError("login_failed", "login was denied");
    if (error === "expired_token") throw new GuardError("login_failed", "the login code expired; start again");
    throw new GuardError("login_failed", `token request failed (HTTP ${status}${error ? `, ${error}` : ""})`);
  }
}

export async function refreshTokens(
  cfg: GuardConfig,
  refreshToken: string,
  deps: { fetch?: FetchLike; now?: () => number } = {},
): Promise<TokenSet> {
  const { status, body } = await postForm(
    deps.fetch ?? fetch,
    endpoints(cfg).token,
    { grant_type: "refresh_token", refresh_token: refreshToken, client_id: cfg.clientId },
    cfg.requestTimeoutMs,
  );
  if (status !== 200) {
    const error = typeof body.error === "string" ? body.error : "";
    throw new GuardError(
      "not_authenticated",
      `session could not be refreshed (HTTP ${status}${error ? `, ${error}` : ""}); run \`opencode auth login\` again`,
    );
  }
  return tokenSetFrom(body, (deps.now ?? Date.now)());
}
