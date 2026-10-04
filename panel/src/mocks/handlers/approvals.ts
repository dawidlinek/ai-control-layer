/** MSW handlers: approvals (list, get, decision). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { approvals } from "../db/approvals";
import type { Approval } from "../db/types";
import type { components } from "@/lib/api/schema";
import { adminPath, MOCK_USER, problem, queryOf } from "./helpers";

type Decision = components["schemas"]["ApprovalDecisionRequest"];

/** "Requests nobody answers are denied after 10 minutes": pending requests past `expires_at` become `expired`. */
function expireOverdue(list: Approval[]): void {
  const now = Date.now();
  for (const a of list) {
    if (a.status === "pending" && new Date(a.expires_at).getTime() <= now) {
      a.status = "expired";
      a.decided_at = a.expires_at;
    }
  }
}

export const approvalsHandlers: HttpHandler[] = [
  http.get(adminPath("/approvals"), ({ request }) => {
    expireOverdue(approvals.items);
    const status = queryOf(request).get("status");
    const list = approvals.items
      .filter((a) => (status ? a.status === status : true))
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/approvals/:id"), ({ params }) => {
    expireOverdue(approvals.items);
    const a = approvals.items.find((x) => x.id === params.id);
    return a ? HttpResponse.json(a) : problem(404, "approval not found");
  }),

  http.post(adminPath("/approvals/:id/decision"), async ({ params, request }) => {
    expireOverdue(approvals.items);
    const a = approvals.items.find((x) => x.id === params.id);
    if (!a) return problem(404, "approval not found");
    if (a.status !== "pending") return problem(409, `approval already ${a.status}`);
    const body = (await request.json()) as Decision;
    if (body.decision !== "approve" && body.decision !== "deny") return problem(422, "decision must be approve or deny");
    a.status = body.decision === "approve" ? "approved" : "denied";
    a.decided_by = MOCK_USER;
    a.decided_at = new Date().toISOString();
    if (body.decision === "approve" && body.elevation_minutes) {
      a.elevation = {
        scope: `tool:${a.server ?? "tool"}.${a.tool ?? "call"}`,
        until: new Date(Date.now() + body.elevation_minutes * 60_000).toISOString(),
      };
    }
    return HttpResponse.json(a);
  }),
];
