/**
 * MSW handlers: models domain. TODO (screen agent): implement the endpoints below on top of ../db/models.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/ModelsConnectors.dc.html
 * Endpoints: /admin/v1/connectors (+ kill-switch), /admin/v1/models
 */
import type { HttpHandler } from "msw";

export const modelsHandlers: HttpHandler[] = [];
