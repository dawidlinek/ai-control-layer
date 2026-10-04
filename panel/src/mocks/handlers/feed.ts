/**
 * MSW handlers: feed domain. TODO (screen agent): implement the endpoints below on top of ../db/feed.ts,
 * using the helpers in ./helpers.ts. Prototype with the demo data: docs/ux/design-reference/FeedArtifacts.dc.html
 * Endpoints: /admin/v1/feed (+ sync), /admin/v1/artifacts (+ scan)
 */
import type { HttpHandler } from "msw";

export const feedHandlers: HttpHandler[] = [];
