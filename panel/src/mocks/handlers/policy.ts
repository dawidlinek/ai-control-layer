/**
 * MSW handlers: policy. Only the status endpoint is served for now.
 * TODO (Policies screen agent): files, validate, dry-run, versions, rollback (see ../db/policy.ts and PolicyEditor.dc.html).
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import { policyStatus } from "../db/policy";
import { adminPath } from "./helpers";

export const policyHandlers: HttpHandler[] = [http.get(adminPath("/policy"), () => HttpResponse.json(policyStatus))];
