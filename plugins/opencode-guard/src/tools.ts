/** Mapping between OpenCode tool ids and the gateway's tool ids (`opencode.<name>` / `<server>.<tool>`). */
import { GuardError } from "./errors.js";

/** Same rule OpenCode uses to build MCP tool names (`<server>_<tool>`, anything outside [A-Za-z0-9_-] becomes `_`). */
export const sanitize = (value: string): string => value.replace(/[^a-zA-Z0-9_-]/g, "_");

export interface ResolvedTool {
  /** Gateway tool id. */
  tool: string;
  /** Governed MCP server name, when the tool belongs to one. */
  server?: string;
}

/**
 * `servers` are the governed MCP servers (those pointing at the gateway's `/mcp/<server>` proxy). Any other tool
 * name is reported as an OpenCode built-in; the gateway's tool allowlist denies ids it does not know, which also
 * covers MCP servers a user tried to add through project config.
 */
export function resolveTool(openCodeTool: string, servers: Iterable<string>): ResolvedTool {
  let best: { server: string; prefixLength: number } | undefined;
  for (const server of servers) {
    const prefix = `${sanitize(server)}_`;
    if (openCodeTool.startsWith(prefix) && openCodeTool.length > prefix.length) {
      if (!best || prefix.length > best.prefixLength) best = { server, prefixLength: prefix.length };
    }
  }
  if (best) return { tool: `${best.server}.${openCodeTool.slice(best.prefixLength)}`, server: best.server };
  return { tool: `opencode.${openCodeTool}` };
}

/** Replace the contents of `target` with `replacement` in place (OpenCode keeps using its original args object). */
export function replaceArgsInPlace(target: unknown, replacement: Record<string, unknown>): void {
  if (!target || typeof target !== "object" || Array.isArray(target)) {
    throw new GuardError("malformed_response", "tool arguments cannot be rewritten; action blocked");
  }
  const obj = target as Record<string, unknown>;
  for (const key of Object.keys(obj)) delete obj[key];
  Object.assign(obj, replacement);
}
