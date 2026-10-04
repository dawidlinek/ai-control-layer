/** MSW handlers: tools domain (MCP servers, tools, approve / quarantine). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { mcpServers, mcpTools } from "../db/tools";
import type { components } from "@/lib/api/schema";
import { adminPath, problem, queryOf } from "./helpers";

type ApprovalRequest = components["schemas"]["McpToolApprovalRequest"];

async function reasonOf(request: Request): Promise<string | null> {
  const body = (await request.json().catch(() => ({}))) as Partial<ApprovalRequest>;
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  return reason || null;
}

export const toolsHandlers: HttpHandler[] = [
  http.get(adminPath("/mcp/servers"), () => HttpResponse.json(mcpServers.items)),

  http.get(adminPath("/mcp/tools"), ({ request }) => {
    const server = queryOf(request).get("server");
    return HttpResponse.json(mcpTools.items.filter((t) => (server ? t.server === server : true)));
  }),

  http.post(adminPath("/mcp/tools/:id/approve"), async ({ params, request }) => {
    const t = mcpTools.items.find((x) => x.id === params.id);
    if (!t) return problem(404, "MCP tool not found");
    if (!(await reasonOf(request))) return problem(422, "reason is required");
    if (t.status === "pinned" && t.pinned_hash === t.current_hash) return problem(409, "this version is already approved");
    t.status = "pinned";
    t.pinned_hash = t.current_hash;
    t.drift_detected_at = null;
    t.description_diff = null;
    return HttpResponse.json(t);
  }),

  http.post(adminPath("/mcp/tools/:id/quarantine"), async ({ params, request }) => {
    const t = mcpTools.items.find((x) => x.id === params.id);
    if (!t) return problem(404, "MCP tool not found");
    if (!(await reasonOf(request))) return problem(422, "reason is required");
    t.status = "quarantined";
    return HttpResponse.json(t);
  }),
];
