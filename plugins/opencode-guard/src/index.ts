/**
 * @corp/opencode-guard - OpenCode plugin for the AI Control Layer.
 *
 *  - `auth`            Keycloak device-code login for provider `company`, refresh in the loader
 *  - `chat.headers`    Authorization / X-Device-Id / X-Client-App / X-Session-Id on every model request
 *  - `tool.execute.before`  POST /v1/decide for every built-in and MCP tool call (fail closed)
 *  - `permission.ask`  denies permission prompts for calls the gateway already refused (defence in depth)
 *  - `config`          pins MCP servers to the gateway's /mcp/<server> proxy and attaches the user's token
 *
 * Verified against @opencode-ai/plugin 1.18.x (see deploy/README-clients.md).
 */
import type { Hooks, Plugin, PluginModule } from "@opencode-ai/plugin";
import { loadConfig, type GuardConfig } from "./config.js";
import { GuardError } from "./errors.js";
import { GatewayClient } from "./gateway.js";
import { Guard } from "./guard.js";
import { buildChatHeaders, makeGuardedFetch } from "./hooks.js";
import { pollDeviceToken, startDeviceFlow } from "./oidc.js";
import { fileAuthLoader, TokenManager } from "./tokens.js";

export { Guard } from "./guard.js";
export { GatewayClient, parseDecideResponse } from "./gateway.js";
export { loadConfig } from "./config.js";
export { TokenManager } from "./tokens.js";
export { GuardError } from "./errors.js";
export { resolveTool } from "./tools.js";

type McpEntry = { type?: string; url?: string; headers?: Record<string, string>; oauth?: unknown; enabled?: boolean };

/** Keep only MCP servers that point at the gateway's /mcp/<server> proxy; attach the user's token to those. */
export function governMcp(
  cfg: GuardConfig,
  tokens: TokenManager,
  mcp: Record<string, McpEntry> | undefined,
  extra: Iterable<string> = [],
): Set<string> {
  const governed = new Set<string>(extra);
  if (!mcp) return governed;
  for (const [name, entry] of Object.entries(mcp)) {
    const ok =
      cfg.problems.length === 0 &&
      entry?.type === "remote" &&
      typeof entry.url === "string" &&
      entry.url.startsWith(`${cfg.gatewayUrl}/mcp/`);
    if (!ok) {
      delete mcp[name];
      governed.delete(name);
      continue;
    }
    governed.add(name);
    entry.oauth = false;
    const headers = (entry.headers ??= {});
    headers["X-Device-Id"] = cfg.deviceId;
    headers["X-Client-App"] = cfg.clientApp;
    // A getter, so a long-lived MCP transport that re-reads its headers per request sees refreshed tokens.
    Object.defineProperty(headers, "Authorization", {
      enumerable: true,
      configurable: true,
      get: () => {
        void tokens.accessToken().catch(() => undefined); // keep the token fresh for the next request
        return `Bearer ${tokens.peek() ?? ""}`;
      },
    });
  }
  return governed;
}

export const server: Plugin = async (input, options) => {
  const cfg = loadConfig(options as Record<string, unknown> | undefined, process.env);
  const tokens = new TokenManager(cfg, {
    load: fileAuthLoader(cfg.providerId),
    save: async (t) => {
      await input.client.auth.set({
        path: { id: cfg.providerId },
        body: { type: "oauth", access: t.access, refresh: t.refresh, expires: t.expires },
      });
    },
  });
  const gateway = new GatewayClient(cfg, tokens);

  const configuredServers = [
    ...(Array.isArray((options as Record<string, unknown> | undefined)?.mcpServers)
      ? ((options as Record<string, unknown>).mcpServers as unknown[]).filter((s): s is string => typeof s === "string")
      : []),
    ...(process.env.ACL_MCP_SERVERS ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  ];
  let governed = new Set<string>(configuredServers);

  const toast = (message: string, variant: "info" | "warning" | "error") => {
    void Promise.resolve(input.client.tui.showToast({ body: { message, variant } })).catch(() => undefined);
  };

  const guard = new Guard({
    cfg,
    gateway,
    directory: input.directory,
    worktree: input.worktree,
    mcpServers: () => governed,
    notify: toast,
  });

  const hooks: Hooks = {
    config: async (config) => {
      governed = governMcp(cfg, tokens, (config as { mcp?: Record<string, McpEntry> }).mcp, configuredServers);
      // MCP clients connect right after this hook: have the stored (or refreshed) token ready for their first request.
      await tokens.accessToken().catch(() => undefined);
    },

    auth: {
      provider: cfg.providerId,
      loader: async (getAuth) => {
        tokens.bind(getAuth as never);
        const info = await getAuth();
        if (!info || info.type !== "oauth") return {};
        void tokens.accessToken().catch(() => undefined); // warm (and refresh) the token for MCP header getters
        return { apiKey: "", fetch: makeGuardedFetch(cfg, tokens) };
      },
      methods: [
        {
          type: "oauth",
          label: "Company SSO (Keycloak device code)",
          authorize: async () => {
            if (cfg.problems.length > 0) {
              throw new GuardError("misconfigured", `guard misconfigured: ${cfg.problems.join("; ")}`);
            }
            const device = await startDeviceFlow(cfg);
            return {
              url: device.verificationUrl,
              instructions: `Open the link, sign in and confirm the code ${device.userCode}.`,
              method: "auto" as const,
              callback: async () => {
                try {
                  const t = await pollDeviceToken(cfg, device);
                  tokens.set(t);
                  return { type: "success" as const, access: t.access, refresh: t.refresh, expires: t.expires };
                } catch {
                  return { type: "failed" as const };
                }
              },
            };
          },
        },
      ],
    },

    "chat.headers": async (hookInput, output) => {
      Object.assign(output.headers, await buildChatHeaders(cfg, tokens, hookInput));
    },

    "tool.execute.before": async (hookInput, output) => {
      await guard.beforeTool(hookInput, output);
    },

    "permission.ask": async (permission, output) => {
      const callID = (permission as { callID?: string }).callID;
      if (callID && guard.wasBlocked(callID)) output.status = "deny";
    },
  };
  return hooks;
};

// OpenCode loads path/npm plugins through the default export; path plugins must carry an id.
const plugin: PluginModule = { id: "corp-opencode-guard", server };
export default plugin;
