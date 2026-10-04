/**
 * A laptop OpenCode talking to the publicly hosted gateway (deploy/opencode-remote): https everywhere, no Keycloak
 * back channel (ACL_OIDC_BASE_URL unset), MCP proxies at https://<gateway>/mcp/<server>.
 */
import { describe, expect, it, vi } from "vitest";
import { isPrivateHttpHost, loadConfig } from "../src/config.js";
import { buildChatHeaders, makeGuardedFetch } from "../src/hooks.js";
import { governMcp, isGatewayMcpUrl } from "../src/index.js";
import { browserUrl, refreshTokens, startDeviceFlow } from "../src/oidc.js";
import { TokenManager } from "../src/tokens.js";

const GW = "https://rogatka-api.b.solvro.pl";
const ISSUER = "https://rogatka-auth.b.solvro.pl/realms/acl";
const REMOTE_ENV = { ACL_GATEWAY_URL: GW, ACL_OIDC_ISSUER: ISSUER, ACL_OIDC_CLIENT_ID: "opencode", ACL_DEVICE_ID: "dev-laptop-01" };

const remote = (env: Record<string, string | undefined> = {}) => loadConfig(undefined, { ...REMOTE_ENV, ...env });
const loggedIn = (cfg = remote()) => {
  const t = new TokenManager(cfg, {});
  t.set({ access: "tok-remote", refresh: "r", expires: Date.now() + 600_000 });
  return t;
};

describe("config for the public https deployment", () => {
  it("accepts https gateway + issuer from env; the back channel defaults to the issuer", () => {
    const cfg = remote();
    expect(cfg.problems).toEqual([]);
    expect(cfg.gatewayUrl).toBe(GW);
    expect(cfg.issuer).toBe(ISSUER);
    expect(cfg.oidcBaseUrl).toBe(ISSUER);
    expect(cfg.clientId).toBe("opencode");
  });

  it("normalises trailing slashes and host case so origin checks are exact", () => {
    const cfg = remote({ ACL_GATEWAY_URL: "https://Rogatka-API.b.solvro.pl/", ACL_OIDC_ISSUER: `${ISSUER}/` });
    expect(cfg.problems).toEqual([]);
    expect(cfg.gatewayUrl).toBe(GW);
    expect(cfg.issuer).toBe(ISSUER);
  });

  it("keeps the container setup valid (plain http to compose service names and localhost)", () => {
    const cfg = loadConfig(undefined, {
      ACL_GATEWAY_URL: "http://gateway:8000",
      ACL_OIDC_ISSUER: "http://localhost:8180/realms/acl",
      ACL_OIDC_BASE_URL: "http://keycloak:8080/realms/acl",
      ACL_DEVICE_ID: "d",
    });
    expect(cfg.problems).toEqual([]);
    expect(cfg.oidcBaseUrl).toBe("http://keycloak:8080/realms/acl");
  });

  it.each([
    ["plain http to a public gateway", { ACL_GATEWAY_URL: "http://rogatka-api.b.solvro.pl" }, /must use https/],
    ["plain http to a public issuer", { ACL_OIDC_ISSUER: "http://rogatka-auth.b.solvro.pl/realms/acl" }, /must use https/],
    ["a gateway URL ending in /v1", { ACL_GATEWAY_URL: `${GW}/v1` }, /without \/v1/],
    ["credentials in the URL", { ACL_GATEWAY_URL: "https://user:pw@rogatka-api.b.solvro.pl" }, /credentials/],
    ["a query string", { ACL_GATEWAY_URL: `${GW}?x=1` }, /query/],
    ["a non-http scheme", { ACL_GATEWAY_URL: "ftp://rogatka-api.b.solvro.pl" }, /http\(s\)/],
    ["a relative URL", { ACL_GATEWAY_URL: "rogatka-api.b.solvro.pl" }, /not a valid URL/],
  ])("rejects %s (guard then fails closed)", (_label, env, message) => {
    const cfg = remote(env);
    expect(cfg.problems.join("; ")).toMatch(message);
  });

  it("ACL_ALLOW_INSECURE_HTTP is an explicit, opt-in escape hatch for lab setups", () => {
    expect(remote({ ACL_GATEWAY_URL: "http://10.0.0.5:8000", ACL_ALLOW_INSECURE_HTTP: "1" }).problems).toEqual([]);
    expect(remote({ ACL_GATEWAY_URL: "http://10.0.0.5:8000" }).problems).not.toEqual([]);
  });

  it("classifies private http hosts", () => {
    for (const h of ["localhost", "app.localhost", "127.0.0.1", "[::1]", "gateway", "keycloak", "gateway.test", "x.internal"]) {
      expect(isPrivateHttpHost(h)).toBe(true);
    }
    for (const h of ["rogatka-api.b.solvro.pl", "api.openai.com", "10.0.0.5", "localhost.evil.com"]) {
      expect(isPrivateHttpHost(h)).toBe(false);
    }
  });
});

describe("token only ever goes to the https gateway origin", () => {
  const inner = () => vi.fn(async (_u: string | URL | Request, _i?: RequestInit) => new Response("{}"));

  it("sets Authorization for https://<gateway>/v1/...", async () => {
    const cfg = remote();
    const f0 = inner();
    await makeGuardedFetch(cfg, loggedIn(cfg), f0)(`${GW}/v1/chat/completions`, { headers: { authorization: "Bearer " } });
    expect((f0.mock.calls[0]![1]!.headers as Headers).get("authorization")).toBe("Bearer tok-remote");
  });

  it("also accepts a Request object for the gateway", async () => {
    const cfg = remote();
    const f0 = inner();
    await makeGuardedFetch(cfg, loggedIn(cfg), f0)(new Request(`${GW}/v1/models`));
    expect(f0).toHaveBeenCalledOnce();
  });

  it.each([
    ["http downgrade of the same host", "http://rogatka-api.b.solvro.pl/v1/chat/completions"],
    ["look-alike host", "https://rogatka-api.b.solvro.pl.evil.example/v1/chat/completions"],
    ["other port", "https://rogatka-api.b.solvro.pl:8443/v1/chat/completions"],
    ["the identity provider", "https://rogatka-auth.b.solvro.pl/v1/chat/completions"],
    ["a model provider", "https://api.openai.com/v1/chat/completions"],
    ["userinfo trick", "https://rogatka-api.b.solvro.pl@evil.example/v1/chat/completions"],
    ["a relative URL", "/v1/chat/completions"],
  ])("refuses %s", async (_label, url) => {
    const cfg = remote();
    const f0 = inner();
    await expect(makeGuardedFetch(cfg, loggedIn(cfg), f0)(url, {})).rejects.toMatchObject({ code: "misconfigured" });
    expect(f0).not.toHaveBeenCalled();
  });

  it("refuses everything when the configuration is invalid", async () => {
    const cfg = remote({ ACL_GATEWAY_URL: "http://rogatka-api.b.solvro.pl" });
    const f0 = inner();
    await expect(makeGuardedFetch(cfg, loggedIn(cfg), f0)("http://rogatka-api.b.solvro.pl/v1/x", {})).rejects.toMatchObject({
      code: "misconfigured",
    });
    expect(f0).not.toHaveBeenCalled();
  });

  it("chat headers carry the token for provider company", async () => {
    const cfg = remote();
    const h = await buildChatHeaders(cfg, loggedIn(cfg), { sessionID: "ses_1", model: { providerID: "company" } });
    expect(h).toMatchObject({ Authorization: "Bearer tok-remote", "X-Device-Id": "dev-laptop-01" });
  });
});

describe("MCP governance against the public gateway", () => {
  it("keeps https://<gateway>/mcp/<name> and drops everything else", () => {
    const cfg = remote();
    const mcp: Record<string, any> = {
      "governed-tools": { type: "remote", url: `${GW}/mcp/governed-tools` },
      files: { type: "remote", url: `${GW}/mcp/files` },
      mail: { type: "remote", url: "https://ROGATKA-API.b.solvro.pl:443/mcp/mail" }, // same origin, normalised by URL
      web: { type: "remote", url: `${GW}/mcp/web`, headers: { Authorization: "Bearer stale" } },
      oldContainer: { type: "remote", url: "http://gateway:8000/mcp/oldContainer" },
      downgrade: { type: "remote", url: "http://rogatka-api.b.solvro.pl/mcp/downgrade" },
      lookalike: { type: "remote", url: "https://rogatka-api.b.solvro.pl.evil.example/mcp/lookalike" },
      userinfo: { type: "remote", url: "https://x@rogatka-api.b.solvro.pl/mcp/userinfo" },
      renamed: { type: "remote", url: `${GW}/mcp/files` }, // key must match the proxied server
      traversal: { type: "remote", url: `${GW}/mcp/../v1/traversal` },
      query: { type: "remote", url: `${GW}/mcp/query?u=https://evil.example` },
      local: { type: "local", command: ["npx", "x"] },
    };
    const governed = governMcp(cfg, loggedIn(cfg), mcp);
    expect([...governed].sort()).toEqual(["files", "governed-tools", "mail", "web"]);
    expect(Object.keys(mcp).sort()).toEqual(["files", "governed-tools", "mail", "web"]);
    expect(mcp.web.headers.Authorization).toBe("Bearer tok-remote");
    expect(mcp.files.oauth).toBe(false);
  });

  it("isGatewayMcpUrl honours a gateway mounted under a path prefix", () => {
    const cfg = remote({ ACL_GATEWAY_URL: "https://corp.example/ai-gateway" });
    expect(isGatewayMcpUrl(cfg, "files", "https://corp.example/ai-gateway/mcp/files")).toBe(true);
    expect(isGatewayMcpUrl(cfg, "files", "https://corp.example/mcp/files")).toBe(false);
  });
});

describe("device-code login straight against the public issuer", () => {
  it("posts to <issuer>/protocol/openid-connect/... and shows Keycloak's https link unchanged", async () => {
    const cfg = remote();
    const seen: string[] = [];
    const fetchImpl = async (url: string, _init?: RequestInit) => {
      seen.push(url);
      return new Response(
        JSON.stringify({
          device_code: "dc",
          user_code: "QWER-TYUI",
          verification_uri: `${ISSUER}/device`,
          verification_uri_complete: `${ISSUER}/device?user_code=QWER-TYUI`,
          expires_in: 600,
          interval: 5,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };
    const d = await startDeviceFlow(cfg, fetchImpl);
    expect(seen).toEqual([`${ISSUER}/protocol/openid-connect/auth/device`]);
    expect(d.verificationUrl).toBe(`${ISSUER}/device?user_code=QWER-TYUI`);
    expect(browserUrl(cfg, `${ISSUER}/device`)).toBe(`${ISSUER}/device`);
  });

  it("refreshes against the issuer's token endpoint", async () => {
    const cfg = remote();
    const seen: string[] = [];
    const fetchImpl = async (url: string, _init?: RequestInit) => {
      seen.push(url);
      return new Response(JSON.stringify({ access_token: "a2", refresh_token: "r2", expires_in: 300 }), { status: 200 });
    };
    expect(await refreshTokens(cfg, "r1", { fetch: fetchImpl })).toMatchObject({ access: "a2" });
    expect(seen).toEqual([`${ISSUER}/protocol/openid-connect/token`]);
  });
});
