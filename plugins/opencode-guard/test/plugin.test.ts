import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin, { governMcp, server } from "../src/index.js";
import { buildChatHeaders, makeGuardedFetch } from "../src/hooks.js";
import { fileAuthLoader, TokenManager } from "../src/tokens.js";
import { DECIDE_OK, json, startServer, testConfig, type TestServer } from "./helpers.js";

const loggedIn = (cfg = testConfig()) => {
  const t = new TokenManager(cfg, {});
  t.set({ access: "tok-1", refresh: "r-1", expires: Date.now() + 600_000 });
  return t;
};

describe("chat.headers", () => {
  it("adds bearer token, device id, client app and the OpenCode session id for the company provider", async () => {
    const cfg = testConfig();
    const h = await buildChatHeaders(cfg, loggedIn(cfg), { sessionID: "ses_abc", model: { providerID: "company" } });
    expect(h).toMatchObject({
      Authorization: "Bearer tok-1",
      "X-Device-Id": "dev-test-0001",
      "X-Client-App": "opencode",
      "X-Session-Id": "ses_abc",
    });
  });

  it("never attaches credentials to another provider's requests", async () => {
    const cfg = testConfig();
    expect(await buildChatHeaders(cfg, loggedIn(cfg), { sessionID: "s", model: { providerID: "openai" } })).toEqual({});
  });

  it("omits Authorization (and so is rejected upstream) when not logged in", async () => {
    const cfg = testConfig();
    const h = await buildChatHeaders(cfg, new TokenManager(cfg, {}), { sessionID: "s", model: { providerID: "company" } });
    expect(h.Authorization).toBeUndefined();
    expect(h["X-Session-Id"]).toBe("s");
  });
});

describe("provider fetch installed by the auth loader", () => {
  it("sets Authorization for the gateway origin", async () => {
    const cfg = testConfig();
    const inner = vi.fn(async (_u: string | URL | Request, _i?: RequestInit) => new Response("{}"));
    const f = makeGuardedFetch(cfg, loggedIn(cfg), inner);
    await f("http://gateway.test:8000/v1/chat/completions", { headers: { "content-type": "application/json", authorization: "Bearer " } });
    const init = inner.mock.calls[0]![1] as RequestInit;
    const headers = init.headers as Headers;
    expect(headers.get("authorization")).toBe("Bearer tok-1");
    expect(headers.get("content-type")).toBe("application/json");
  });

  it("refuses any other origin (token never leaves for another host)", async () => {
    const cfg = testConfig();
    const inner = vi.fn(async (_u: string | URL | Request, _i?: RequestInit) => new Response("{}"));
    const f = makeGuardedFetch(cfg, loggedIn(cfg), inner);
    await expect(f("https://api.openai.com/v1/chat/completions", {})).rejects.toMatchObject({ code: "misconfigured" });
    expect(inner).not.toHaveBeenCalled();
  });
});

describe("MCP governance (config hook)", () => {
  it("keeps only gateway /mcp/<server> proxies, forces oauth off and attaches a live bearer", async () => {
    const cfg = testConfig();
    const tokens = loggedIn(cfg);
    const mcp: Record<string, any> = {
      files: { type: "remote", url: "http://gateway.test:8000/mcp/files" },
      evil: { type: "remote", url: "https://evil.example/mcp" },
      local: { type: "local", command: ["npx", "x"] },
    };
    const governed = governMcp(cfg, tokens, mcp);
    expect([...governed]).toEqual(["files"]);
    expect(Object.keys(mcp)).toEqual(["files"]);
    expect(mcp.files.oauth).toBe(false);
    expect(mcp.files.headers.Authorization).toBe("Bearer tok-1");
    expect({ ...mcp.files.headers }.Authorization).toBe("Bearer tok-1"); // enumerable (spread by HTTP clients)
    tokens.set({ access: "tok-2", refresh: "r", expires: Date.now() + 600_000 });
    expect(mcp.files.headers.Authorization).toBe("Bearer tok-2"); // follows refreshes
  });

  it("removes every MCP server when the guard is misconfigured", () => {
    const cfg = testConfig({ gatewayUrl: "" });
    const mcp: Record<string, any> = { files: { type: "remote", url: "/mcp/files" } };
    governMcp(cfg, loggedIn(cfg), mcp);
    expect(mcp).toEqual({});
  });
});

describe("plugin wiring against mocked gateway + Keycloak", () => {
  let gw: TestServer;
  let kc: TestServer;
  let auth: Record<string, unknown>;
  const toasts: string[] = [];

  beforeEach(async () => {
    gw = await startServer((_r, res) => json(res, 200, DECIDE_OK));
    kc = await startServer((r, res) => {
      if (r.url?.endsWith("/auth/device")) {
        return json(res, 200, {
          device_code: "dc",
          user_code: "WXYZ-1234",
          verification_uri: `${kc.url}/realms/acl/device`,
          verification_uri_complete: `${kc.url}/realms/acl/device?user_code=WXYZ-1234`,
          expires_in: 600,
          interval: 0.001,
        });
      }
      json(res, 200, { access_token: "a-new", refresh_token: "r-new", expires_in: 900 });
    });
    auth = {};
    process.env.ACL_GATEWAY_URL = gw.url;
    process.env.ACL_OIDC_ISSUER = "http://localhost:8180/realms/acl";
    process.env.ACL_OIDC_BASE_URL = `${kc.url}/realms/acl`;
    process.env.ACL_DEVICE_ID = "dev-plugin-test";
    process.env.XDG_DATA_HOME = mkdtempSync(join(tmpdir(), "guard-xdg-"));
  });
  afterEach(async () => {
    await gw.close();
    await kc.close();
    for (const k of ["ACL_GATEWAY_URL", "ACL_OIDC_ISSUER", "ACL_OIDC_BASE_URL", "ACL_DEVICE_ID", "XDG_DATA_HOME"]) delete process.env[k];
  });

  const input = () =>
    ({
      directory: "/workspace/demo",
      worktree: "/workspace/demo",
      client: {
        auth: { set: async (a: unknown) => void (auth = a as Record<string, unknown>) },
        tui: { showToast: async ({ body }: { body: { message: string } }) => void toasts.push(body.message) },
      },
    }) as never;

  it("default export is a V1 plugin module with an id (required for path plugins)", () => {
    expect(plugin.id).toBe("corp-opencode-guard");
    expect(plugin.server).toBe(server);
  });

  it("device login -> stored tokens -> guarded tool call reaches /v1/decide with the new token", async () => {
    const hooks = await server(input(), undefined);
    const method = hooks.auth!.methods[0]!;
    expect(method.type).toBe("oauth");
    const started = await (method as any).authorize();
    expect(started.instructions).toContain("WXYZ-1234");
    expect(started.url).toBe("http://localhost:8180/realms/acl/device?user_code=WXYZ-1234");
    expect(started.method).toBe("auto");
    const done = await started.callback();
    expect(done).toMatchObject({ type: "success", access: "a-new", refresh: "r-new" });
    expect(JSON.stringify(started)).not.toContain("a-new");

    await hooks["tool.execute.before"]!({ tool: "read", sessionID: "ses_9", callID: "c9" }, { args: { filePath: "x" } });
    const decide = gw.requests.find((r) => r.url === "/v1/decide")!;
    expect(decide.headers.authorization).toBe("Bearer a-new");
    expect(JSON.parse(decide.body)).toMatchObject({ session_id: "ses_9", action: { tool: "opencode.read", tool_call_id: "c9" } });
  });

  it("blocks with the rule id and denies the follow-up permission prompt for that call", async () => {
    gw.setHandler((_r, res) =>
      json(res, 200, { ...DECIDE_OK, action: "block", rule_ids: ["SEC-PATH-01"], reason: "outside workspace" }),
    );
    const hooks = await server(input(), undefined);
    const login = await (hooks.auth!.methods[0] as any).authorize();
    await login.callback();
    await expect(
      hooks["tool.execute.before"]!({ tool: "read", sessionID: "s", callID: "c1" }, { args: { filePath: "/home/dev/.ssh/id_rsa" } }),
    ).rejects.toThrow(/SEC-PATH-01/);
    const out = { status: "ask" as "ask" | "deny" | "allow" };
    await hooks["permission.ask"]!({ callID: "c1" } as never, out);
    expect(out.status).toBe("deny");
    const other = { status: "ask" as "ask" | "deny" | "allow" };
    await hooks["permission.ask"]!({ callID: "other" } as never, other);
    expect(other.status).toBe("ask");
  });

  it("without a login every tool call is blocked (fail closed)", async () => {
    const hooks = await server(input(), undefined);
    await expect(
      hooks["tool.execute.before"]!({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "ls" } }),
    ).rejects.toMatchObject({ code: "not_authenticated" });
    expect(gw.requests).toHaveLength(0);
  });

  it("chat.headers hook fills the output headers", async () => {
    const hooks = await server(input(), undefined);
    const login = await (hooks.auth!.methods[0] as any).authorize();
    await login.callback();
    const output = { headers: {} as Record<string, string> };
    await hooks["chat.headers"]!({ sessionID: "ses_h", model: { providerID: "company" } } as never, output);
    expect(output.headers).toMatchObject({ "X-Session-Id": "ses_h", "X-Client-App": "opencode", Authorization: "Bearer a-new" });
  });

  it("loader: no stored OAuth login -> no provider overrides; stored login -> custom fetch", async () => {
    const hooks = await server(input(), undefined);
    expect(await hooks.auth!.loader!((async () => undefined) as never, {} as never)).toEqual({});
    const opts = await hooks.auth!.loader!(
      (async () => ({ type: "oauth", access: "a", refresh: "r", expires: Date.now() + 600_000 })) as never,
      {} as never,
    );
    expect(opts.apiKey).toBe("");
    expect(typeof opts.fetch).toBe("function");
  });

  it("missing configuration: plugin still loads, but every tool call is blocked and login refuses", async () => {
    delete process.env.ACL_GATEWAY_URL;
    const hooks = await server(input(), undefined);
    await expect(
      hooks["tool.execute.before"]!({ tool: "read", sessionID: "s", callID: "c" }, { args: {} }),
    ).rejects.toMatchObject({ code: "misconfigured" });
    await expect((hooks.auth!.methods[0] as any).authorize()).rejects.toMatchObject({ code: "misconfigured" });
  });
});

describe("fileAuthLoader (OpenCode credential store, read-only)", () => {
  it("reads the provider entry from <XDG_DATA_HOME>/opencode/auth.json", async () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-auth-"));
    mkdirSync(join(dir, "opencode"));
    writeFileSync(
      join(dir, "opencode", "auth.json"),
      JSON.stringify({ company: { type: "oauth", access: "a", refresh: "r", expires: 1 }, openai: { type: "api", key: "k" } }),
    );
    expect(await fileAuthLoader("company", { XDG_DATA_HOME: dir })()).toMatchObject({ type: "oauth", access: "a" });
    expect(await fileAuthLoader("missing", { XDG_DATA_HOME: dir })()).toBeUndefined();
  });

  it("missing or corrupt file -> undefined (not logged in)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-auth-"));
    expect(await fileAuthLoader("company", { XDG_DATA_HOME: dir })()).toBeUndefined();
    mkdirSync(join(dir, "opencode"));
    writeFileSync(join(dir, "opencode", "auth.json"), "{not json");
    expect(await fileAuthLoader("company", { XDG_DATA_HOME: dir })()).toBeUndefined();
  });
});
