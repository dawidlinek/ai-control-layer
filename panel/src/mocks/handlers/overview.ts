/** MSW handlers: overview domain (`/admin/v1/metrics/overview?window=15m|1h|24h|7d`). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { buildOverview, parseWindow } from "../db/overview";
import { adminPath, queryOf } from "./helpers";

export const overviewHandlers: HttpHandler[] = [
  http.get(adminPath("/metrics/overview"), ({ request }) =>
    HttpResponse.json(buildOverview(parseWindow(queryOf(request).get("window")))),
  ),
];
