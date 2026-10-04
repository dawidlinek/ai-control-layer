/**
 * MSW handlers: insights domain. TODO (screen agent): implement the endpoints below on top of ../db/insights.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/Insights.dc.html
 * Endpoints: /admin/v1/insights/clusters (+ publish)
 */
import type { HttpHandler } from "msw";

export const insightsHandlers: HttpHandler[] = [];
