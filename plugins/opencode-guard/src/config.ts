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
  /** Gateway origin, e.g. `http://gateway:8000` (no trailing slash, no `/v1`). */
  gatewayUrl: string;
  /** Token issuer as users' browsers see it, e.g. `http://localhost:8180/realms/acl`. Used for UI links. */
  issuer: string;
  /** Where this process reaches Keycloak (realm URL). Defaults to the issuer. */
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
  /** Admin panel origin for "decide here" links in approval notices (optional, display only). */
  panelUrl?: string;
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

function validUrl(value: string | undefined, name: string, problems: string[]): string {
  if (!value) {
    problems.push(`${name} is not configured`);
    return "";
  }
  try {
    new URL(value);
    return stripSlash(value);
  } catch {
    problems.push(`${name} is not a valid URL`);
    return "";
  }
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

/** Display-only URL: an invalid value just drops the link. */
function optionalUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    return stripSlash(new URL(value).toString());
  } catch {
    return undefined;
  }
}

export function loadConfig(options: Options, env: Env = process.env): GuardConfig {
  const problems: string[] = [];
  const gatewayUrl = validUrl(str(options, "gatewayUrl", env, "ACL_GATEWAY_URL"), "gatewayUrl (ACL_GATEWAY_URL)", problems);
  const issuer = validUrl(str(options, "issuer", env, "ACL_OIDC_ISSUER"), "issuer (ACL_OIDC_ISSUER)", problems);
  const oidcBase = str(options, "oidcBaseUrl", env, "ACL_OIDC_BASE_URL");
  const oidcBaseUrl = oidcBase ? validUrl(oidcBase, "oidcBaseUrl (ACL_OIDC_BASE_URL)", problems) : issuer;
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
    panelUrl: optionalUrl(str(options, "panelUrl", env, "ACL_PANEL_URL")),
    problems,
  };
}
