/**
 * MSW handlers: tools domain. TODO (screen agent): implement the endpoints below on top of ../db/tools.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/ToolsMcp.dc.html
 * Endpoints: /admin/v1/mcp/servers, /admin/v1/mcp/tools (+ approve / quarantine)
 */
import type { HttpHandler } from "msw";

export const toolsHandlers: HttpHandler[] = [];
