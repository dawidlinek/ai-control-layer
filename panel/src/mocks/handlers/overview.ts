/** MSW handlers: overview domain (`/admin/v1/metrics/overview?window=15m|1h|24h|7d`). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { buildOverview, parseWindow } from "../db/overview";
import { approvals } from "../db/approvals";
import { incidents } from "../db/incidents";
import { mcpTools } from "../db/tools";
import { adminPath, queryOf } from "./helpers";

export const overviewHandlers: HttpHandler[] = [
  // Sidebar badges: open = open + triaged incidents, pending approvals that have not run out, quarantined MCP tools.
  http.get(adminPath("/metrics/counts"), () =>
    HttpResponse.json({
      open_incidents: incidents.items.filter((i) => i.status === "open" || i.status === "triaged").length,
      pending_approvals: approvals.items.filter((a) => a.status === "pending" && Date.parse(a.expires_at) > Date.now()).length,
      quarantined_tools: mcpTools.items.filter((t) => t.status === "quarantined").length,
    }),
  ),

  http.get(adminPath("/metrics/overview"), ({ request }) =>
    HttpResponse.json(buildOverview(parseWindow(queryOf(request).get("window")))),
  ),
];
