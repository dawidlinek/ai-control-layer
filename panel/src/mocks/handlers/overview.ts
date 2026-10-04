/**
 * MSW handlers: overview domain. TODO (screen agent): implement the endpoints below on top of ../db/overview.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/Dashboard.dc.html
 * Endpoints: /admin/v1/metrics/overview
 */
import type { HttpHandler } from "msw";

export const overviewHandlers: HttpHandler[] = [];
