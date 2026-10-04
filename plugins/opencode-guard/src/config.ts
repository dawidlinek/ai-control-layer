/**
 * Plugin configuration. Everything comes from the plugin options tuple in the managed config
 * (`"plugin": [["file:///opt/opencode-guard", {...}]]`) or from the environment. Nothing secret lives here:
 * the only credential is the user's own Keycloak token, obtained at run time through the device-code flow.
 */
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { hostname, homedir } from "node:os";
import { join } from "node:path";

export interface GuardConfig {
  /** OpenCode provider id the auth hook / headers apply to (must match `provider.<id>` in the managed config). */
  providerId: string;
  /**
   * Gateway base URL without `/v1` and without a trailing slash: `http://gateway:8000` in the locked container,
   * `https://rogatka-api.b.solvro.pl` from a laptop. Model calls, `/v1/decide` and the `/mcp/<server>` proxies all
   * derive from it; the bearer token is only ever sent to its origin.
   */
  gatewayUrl: string;
  /**
   * Token issuer (realm URL) as users' browsers see it, e.g. `http://localhost:8180/realms/acl` or
   * `https://rogatka-auth.b.solvro.pl/realms/acl`. Used for the device-code link.
   */
  issuer: string;
  /** Where this process reaches Keycloak (realm URL). `ACL_OIDC_BASE_URL` when set (container back channel), else the issuer. */
  oidcBaseUrl: string;
  clientId: string;
  scope: string;
  deviceId: string;
  clientApp: string;
  clientVersion: string;
  /** Upper bound for a single /v1/decide or approval HTTP call. */
  requestTimeoutMs: number;
  /** How long a `require_approval` call may wait in total. */
  approvalTimeoutMs: number;
  approvalPollMs: number;
  /** Problems found while loading; the guard blocks every tool call while this is non-empty (fail closed). */
  problems: string[];
}

type Env = Record<string, string | undefined>;
type Options = Record<string, unknown> | undefined;

function str(options: Options, key: string, env: Env, envKey: string): string | undefined {
  const fromOptions = options?.[key];
  if (typeof fromOptions === "string" && fromOptions.trim()) return fromOptions.trim();
  const fromEnv = env[envKey];
  return fromEnv && fromEnv.trim() ? fromEnv.trim() : undefined;
}

function num(options: Options, key: string, env: Env, envKey: string, fallback: number): number {
  const raw = options?.[key] ?? env[envKey];
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function stripSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * Hosts that may be reached over plain HTTP: loopback, single-label names (compose service names such as `gateway`,
 * `keycloak`) and reserved non-public suffixes. Anything else carries bearer tokens and must use HTTPS.
 */
export function isPrivateHttpHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || /^127\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (!host.includes(".") && !host.includes(":")) return true;
  return [".test", ".internal", ".local"].some((suffix) => host.endsWith(suffix));
}

function truthy(value: string | undefined): boolean {
  return !!value && ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

/**
 * Validates and normalises a base URL: http(s) only, no credentials, query or fragment, no trailing slash, scheme and
 * host lower-cased (so origin comparisons elsewhere are exact). Plain HTTP only for private hosts unless explicitly allowed.
 */
function validUrl(value: string | undefined, name: string, problems: string[], allowInsecureHttp: boolean): string {
  if (!value) {
    problems.push(`${name} is not configured`);
    return "";
  }
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    problems.push(`${name} is not a valid URL`);
    return "";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    problems.push(`${name} must be an http(s) URL`);
    return "";
  }
  if (u.username || u.password || u.search || u.hash) {
    problems.push(`${name} must not contain credentials, a query or a fragment`);
    return "";
  }
  if (u.protocol === "http:" && !allowInsecureHttp && !isPrivateHttpHost(u.hostname)) {
    problems.push(`${name} must use https for a public host (set ACL_ALLOW_INSECURE_HTTP=1 only for a lab setup)`);
    return "";
  }
  return stripSlash(`${u.origin}${u.pathname}`);
}

/** Stable per-device id: env override, else a random id persisted under the user's state dir, else a hostname hash. */
export function resolveDeviceId(env: Env, home: string = homedir()): string {
  const fromEnv = env.ACL_DEVICE_ID?.trim();
  if (fromEnv) return fromEnv;
  const base = env.XDG_STATE_HOME?.trim() || join(home, ".local", "state");
  const dir = join(base, "opencode-guard");
  const file = join(dir, "device-id");
  try {
    if (existsSync(file)) {
      const existing = readFileSync(file, "utf8").trim();
      if (/^[A-Za-z0-9._-]{8,128}$/.test(existing)) return existing;
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const fresh = `dev-${randomUUID()}`;
    writeFileSync(file, `${fresh}\n`, { mode: 0o600 });
    return fresh;
  } catch {
    return `host-${createHash("sha256").update(hostname()).digest("hex").slice(0, 16)}`;
  }
}

export function loadConfig(options: Options, env: Env = process.env): GuardConfig {
  const problems: string[] = [];
  const insecure = options?.allowInsecureHttp === true || truthy(env.ACL_ALLOW_INSECURE_HTTP);
  const gatewayName = "gatewayUrl (ACL_GATEWAY_URL)";
  const gatewayUrl = validUrl(str(options, "gatewayUrl", env, "ACL_GATEWAY_URL"), gatewayName, problems, insecure);
  if (/\/v1$/.test(gatewayUrl)) problems.push(`${gatewayName} must be the gateway base URL without /v1`);
  const issuer = validUrl(str(options, "issuer", env, "ACL_OIDC_ISSUER"), "issuer (ACL_OIDC_ISSUER)", problems, insecure);
  const oidcBase = str(options, "oidcBaseUrl", env, "ACL_OIDC_BASE_URL");
  const oidcBaseUrl = oidcBase
    ? validUrl(oidcBase, "oidcBaseUrl (ACL_OIDC_BASE_URL)", problems, insecure)
    : issuer;
  return {
    providerId: str(options, "providerId", env, "ACL_PROVIDER_ID") ?? "company",
    gatewayUrl,
    issuer,
    oidcBaseUrl,
    clientId: str(options, "clientId", env, "ACL_OIDC_CLIENT_ID") ?? "opencode",
    scope: str(options, "scope", env, "ACL_OIDC_SCOPE") ?? "openid profile email",
    deviceId: str(options, "deviceId", env, "ACL_DEVICE_ID") ?? resolveDeviceId(env),
    clientApp: "opencode",
    clientVersion: str(options, "clientVersion", env, "ACL_CLIENT_VERSION") ?? "unknown",
    requestTimeoutMs: num(options, "requestTimeoutMs", env, "ACL_REQUEST_TIMEOUT_MS", 15_000),
    approvalTimeoutMs: num(options, "approvalTimeoutMs", env, "ACL_APPROVAL_TIMEOUT_MS", 300_000),
    approvalPollMs: num(options, "approvalPollMs", env, "ACL_APPROVAL_POLL_MS", 2_000),
    problems,
  };
}
