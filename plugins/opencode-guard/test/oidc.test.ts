import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { browserUrl, pollDeviceToken, refreshTokens, startDeviceFlow } from "../src/oidc.js";
import { REFRESH_SKEW_MS, TokenManager } from "../src/tokens.js";
import { json, startServer, testConfig, type Recorded, type TestServer } from "./helpers.js";

/** A mocked Keycloak: device authorization + token endpoints for realm `acl`. */
let kc: TestServer;
let polls: number;
let script: string[]; // token endpoint answers for the device grant, in order

const REALM = "/realms/acl/protocol/openid-connect";
function form(r: Recorded): URLSearchParams {
  return new URLSearchParams(r.body);
}

beforeEach(async () => {
  polls = 0;
  script = [];
  kc = await startServer((r, res) => {
    if (r.url === `${REALM}/auth/device`) {
      return json(res, 200, {
        device_code: "DEVCODE-secret",
        user_code: "ABCD-EFGH",
        verification_uri: `${kc.url}/realms/acl/device`,
        verification_uri_complete: `${kc.url}/realms/acl/device?user_code=ABCD-EFGH`,
        expires_in: 600,
        interval: 5,
      });
    }
    if (r.url === `${REALM}/token`) {
      const f = form(r);
      if (f.get("grant_type") === "refresh_token") {
        return f.get("refresh_token") === "good-refresh"
          ? json(res, 200, { access_token: "access-2", refresh_token: "refresh-2", expires_in: 900 })
          : json(res, 400, { error: "invalid_grant" });
      }
      const step = script[polls++] ?? "authorization_pending";
      if (step === "ok") return json(res, 200, { access_token: "access-1", refresh_token: "refresh-1", expires_in: 900 });
      return json(res, 400, { error: step });
    }
    json(res, 404, {});
  });
});
afterEach(async () => {
  await kc.close();
});

const cfg = () =>
  testConfig({ oidcBaseUrl: `${kc.url}/realms/acl`, issuer: "http://localhost:8180/realms/acl", clientId: "opencode" });

describe("device authorization (RFC 8628) against a mocked Keycloak", () => {
  it("starts the flow as the public client `opencode` and returns user code + browser URL", async () => {
    const d = await startDeviceFlow(cfg());
    const sent = form(kc.requests[0]!);
    expect(sent.get("client_id")).toBe("opencode");
    expect(sent.get("scope")).toContain("openid");
    expect(sent.get("client_secret")).toBeNull(); // public client: no secret
    expect(d.userCode).toBe("ABCD-EFGH");
    expect(d.intervalMs).toBe(5000);
    expect(d.verificationUrl).toBe("http://localhost:8180/realms/acl/device?user_code=ABCD-EFGH"); // origin rewritten for the browser
  });

  it("polls through authorization_pending and slow_down, then returns tokens", async () => {
    script = ["authorization_pending", "slow_down", "ok"];
    const sleeps: number[] = [];
    const d = await startDeviceFlow(cfg());
    const t = await pollDeviceToken(cfg(), d, { sleep: async (ms) => void sleeps.push(ms) });
    expect(t.access).toBe("access-1");
    expect(t.refresh).toBe("refresh-1");
    expect(t.expires).toBeGreaterThan(Date.now());
    expect(sleeps).toEqual([5000, 5000, 10_000]); // slow_down adds 5 s
    const poll = form(kc.requests[1]!);
    expect(poll.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(poll.get("device_code")).toBe("DEVCODE-secret");
  });

  it.each([
    ["access_denied", /denied/],
    ["expired_token", /expired/],
  ])("%s ends the flow with a clear error", async (error, message) => {
    script = [error];
    const d = await startDeviceFlow(cfg());
    await expect(pollDeviceToken(cfg(), d, { sleep: async () => undefined })).rejects.toThrow(message);
  });

  it("gives up when the code's lifetime has passed", async () => {
    const d = await startDeviceFlow(cfg());
    let t = d.expiresAt - 1000;
    await expect(
      pollDeviceToken(cfg(), d, { sleep: async () => void (t += 2000), now: () => t }),
    ).rejects.toThrow(/expired/);
  });

  it("error messages never contain tokens or the device code", async () => {
    script = ["invalid_request"];
    const d = await startDeviceFlow(cfg());
    const err = (await pollDeviceToken(cfg(), d, { sleep: async () => undefined }).catch((e: unknown) => e)) as Error;
    expect(err.message).not.toContain("DEVCODE-secret");
  });

  it("start failure (HTTP error) is a login error", async () => {
    kc.setHandler((_r, res) => json(res, 400, { error: "unauthorized_client" }));
    await expect(startDeviceFlow(cfg())).rejects.toMatchObject({ code: "login_failed" });
  });

  it("browserUrl leaves URLs alone when front and back channel share an origin", () => {
    const same = testConfig({ oidcBaseUrl: "http://localhost:8180/realms/acl", issuer: "http://localhost:8180/realms/acl" });
    expect(browserUrl(same, "http://localhost:8180/realms/acl/device")).toBe("http://localhost:8180/realms/acl/device");
  });
});

describe("refresh", () => {
  it("exchanges the refresh token", async () => {
    const t = await refreshTokens(cfg(), "good-refresh");
    expect(t.access).toBe("access-2");
    expect(form(kc.requests[0]!).get("grant_type")).toBe("refresh_token");
  });

  it("an invalid refresh token asks the user to log in again", async () => {
    await expect(refreshTokens(cfg(), "bad")).rejects.toMatchObject({ code: "not_authenticated" });
  });
});

describe("TokenManager", () => {
  it("returns undefined when never logged in", async () => {
    const m = new TokenManager(cfg(), { load: async () => undefined });
    expect(await m.accessToken()).toBeUndefined();
  });

  it("uses the stored token while fresh and does not refresh", async () => {
    const m = new TokenManager(cfg(), {
      load: async () => ({ type: "oauth", access: "stored", refresh: "good-refresh", expires: Date.now() + 10 * REFRESH_SKEW_MS }),
    });
    expect(await m.accessToken()).toBe("stored");
    expect(kc.requests).toHaveLength(0);
  });

  it("refreshes shortly before expiry (single flight) and saves the result", async () => {
    const saved: string[] = [];
    const m = new TokenManager(cfg(), {
      load: async () => ({ type: "oauth", access: "old", refresh: "good-refresh", expires: Date.now() + 1000 }),
      save: async (t) => void saved.push(t.access),
    });
    const [a, b] = await Promise.all([m.accessToken(), m.accessToken()]);
    expect([a, b]).toEqual(["access-2", "access-2"]);
    expect(kc.requests).toHaveLength(1);
    expect(saved).toEqual(["access-2"]);
  });

  it("a failed refresh surfaces an error (and does not keep serving the stale token)", async () => {
    const m = new TokenManager(cfg(), {
      load: async () => ({ type: "oauth", access: "old", refresh: "bad", expires: Date.now() - 1 }),
    });
    await expect(m.accessToken()).rejects.toMatchObject({ code: "not_authenticated" });
    expect(m.peek()).toBeUndefined();
  });

  it("ignores stored auth of another type", async () => {
    const m = new TokenManager(cfg(), { load: async () => ({ type: "api" }) });
    expect(await m.accessToken()).toBeUndefined();
  });
});
