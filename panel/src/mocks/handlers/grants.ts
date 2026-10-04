/**
 * MSW handlers: grants domain. TODO (screen agent): implement the endpoints below on top of ../db/grants.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/Grants.dc.html
 * Endpoints: /admin/v1/grants, /admin/v1/grants/changes
 */
import type { HttpHandler } from "msw";

export const grantsHandlers: HttpHandler[] = [];
