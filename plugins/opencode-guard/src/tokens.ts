/** In-memory token holder: reads OpenCode's stored auth, refreshes shortly before expiry (single flight), saves back. */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";
import { refreshTokens, type FetchLike, type TokenSet } from "./oidc.js";

export interface StoredAuth {
  type: string;
  access?: string;
  refresh?: string;
  expires?: number;
}

export interface TokenManagerDeps {
  fetch?: FetchLike;
  now?: () => number;
  /** Persist refreshed tokens (OpenCode `client.auth.set`). Failures are non-fatal: the in-memory copy stays valid. */
  save?: (tokens: TokenSet) => Promise<void>;
  /** Supplies OpenCode's stored auth. Bound by the auth loader. */
  load?: () => Promise<StoredAuth | undefined>;
}

/** Refresh when fewer than this many ms remain. */
export const REFRESH_SKEW_MS = 30_000;

/**
 * Reads OpenCode's own credential store (`<XDG_DATA_HOME>/opencode/auth.json`). Used before the auth loader has
 * run (the `config` hook fires first and MCP clients connect right after it); the loader's `getAuth` takes over
 * once bound. Read-only: OpenCode remains the only writer.
 */
export function fileAuthLoader(
  providerId: string,
  env: Record<string, string | undefined> = process.env,
): () => Promise<StoredAuth | undefined> {
  return async () => {
    try {
      const base = env.XDG_DATA_HOME?.trim() || join(homedir(), ".local", "share");
      const parsed: unknown = JSON.parse(await readFile(join(base, "opencode", "auth.json"), "utf8"));
      const entry = (parsed as Record<string, unknown> | null)?.[providerId];
      return entry && typeof entry === "object" ? (entry as StoredAuth) : undefined;
    } catch {
      return undefined;
    }
  };
}

export class TokenManager {
  private current: TokenSet | undefined;
  private inflight: Promise<TokenSet> | undefined;
  private load: (() => Promise<StoredAuth | undefined>) | undefined;

  constructor(
    private readonly cfg: GuardConfig,
    private readonly deps: TokenManagerDeps = {},
  ) {
    this.load = deps.load;
  }

  bind(load: () => Promise<StoredAuth | undefined>): void {
    this.load = load;
  }

  /** The current access token without any I/O (may be stale); undefined before the first read. */
  peek(): string | undefined {
    return this.current?.access;
  }

  /** Seed from a login that just completed. */
  set(tokens: TokenSet): void {
    this.current = tokens;
  }

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  private async read(): Promise<TokenSet | undefined> {
    if (this.current) return this.current;
    if (!this.load) return undefined;
    const stored = await this.load();
    if (stored?.type === "oauth" && stored.access && stored.refresh) {
      this.current = { access: stored.access, refresh: stored.refresh, expires: stored.expires ?? 0 };
    }
    return this.current;
  }

  /** A valid access token, or undefined when the user has not logged in. Throws when a needed refresh fails. */
  async accessToken(): Promise<string | undefined> {
    const tokens = await this.read();
    if (!tokens) return undefined;
    if (tokens.expires - this.now() > REFRESH_SKEW_MS) return tokens.access;
    this.inflight ??= this.refresh(tokens).finally(() => {
      this.inflight = undefined;
    });
    return (await this.inflight).access;
  }

  /** Like accessToken but a missing login is an error (used where a call without credentials is pointless). */
  async requireAccessToken(): Promise<string> {
    const token = await this.accessToken();
    if (!token) throw new GuardError("not_authenticated", "not logged in; run `opencode auth login` (provider: company)");
    return token;
  }

  private async refresh(old: TokenSet): Promise<TokenSet> {
    try {
      const fresh = await refreshTokens(this.cfg, old.refresh, { fetch: this.deps.fetch, now: this.deps.now });
      this.current = fresh;
      try {
        await this.deps.save?.(fresh);
      } catch {
        /* persisting is best effort */
      }
      return fresh;
    } catch (err) {
      this.current = undefined;
      throw err;
    }
  }
}
