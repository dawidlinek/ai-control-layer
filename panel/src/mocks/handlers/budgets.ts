/**
 * MSW handlers: budgets domain. TODO (screen agent): implement the endpoints below on top of ../db/budgets.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/Budgets.dc.html
 * Endpoints: /admin/v1/budgets, /admin/v1/budgets/breakers (+ reset)
 */
import type { HttpHandler } from "msw";

export const budgetsHandlers: HttpHandler[] = [];
