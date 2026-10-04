/**
 * MSW handlers: grants (list, create, revoke, change log), on top of ../db/grants.ts.
 * Mirrors the gateway (api/admin/access.py): `active` defaults to true, `expires_at` must be in the future,
 * an allow grant that an org lock forbids outright is a 422, revoking needs a reason (404 / 409 otherwise).
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import type { components } from "@/lib/api/schema";
import { grantChanges, grants, nextGrantId, recordGrantChange } from "../db/grants";
import type { Grant } from "../db/types";
import { findGroup, findUser } from "../db/users";
import { adminPath, intParam, MOCK_USER, problem, queryOf } from "./helpers";

type GrantCreate = components["schemas"]["GrantCreate"];

/** Cloud model aliases / ids (LOCK-01: confidential and restricted data never go to them). */
const CLOUD = new Set(["smart", "smart-pro", "gemini/flash", "gemini/pro"]);

function refreshActive(g: Grant): Grant {
  const expired = g.expires_at !== null && new Date(g.expires_at).getTime() <= Date.now();
  g.active = !g.revoked_at && !expired;
  return g;
}

export const grantsHandlers: HttpHandler[] = [
  http.get(adminPath("/grants/changes"), ({ request }) => {
    const q = queryOf(request);
    const subject = q.get("subject")?.replace(/^\//, "");
    const list = [...grantChanges.items]
      .filter((c) => (subject ? c.snapshot.subject === subject : true))
      .sort((a, b) => b.id - a.id)
      .slice(0, intParam(q, "limit", 100));
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/grants"), ({ request }) => {
    const q = queryOf(request);
    const subject = q.get("subject")?.replace(/^\//, "");
    const resourceType = q.get("resource_type");
    const resource = q.get("resource");
    const activeParam = q.get("active");
    const active = activeParam === null ? true : activeParam === "true" ? true : activeParam === "false" ? false : null;
    const list = grants.items
      .map(refreshActive)
      .filter((g) => (subject ? g.subject === subject : true))
      .filter((g) => (resourceType ? g.resource_type === resourceType : true))
      .filter((g) => (resource ? g.resource === resource : true))
      .filter((g) => (active === null ? true : g.active === active))
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    return HttpResponse.json(list);
  }),

  http.post(adminPath("/grants"), async ({ request }) => {
    const body = (await request.json()) as GrantCreate;
    if (!body.reason || body.reason.trim().length < 3) return problem(422, "reason must be at least 3 characters");
    if (body.expires_at && new Date(body.expires_at).getTime() <= Date.now()) return problem(422, "expires_at must be in the future");
    const subject = body.subject.replace(/^\//, "");
    if (body.subject_type === "user" ? !findUser(subject) : !findGroup(subject)) return problem(422, `unknown ${body.subject_type} '${subject}'`);
    const effect = body.effect ?? "allow";
    const classes = body.constraints?.data_classes ?? [];
    if (effect === "allow" && CLOUD.has(body.resource) && classes.some((c) => c === "confidential" || c === "restricted")) {
      return problem(422, `org lock LOCK-01 forbids ${body.resource_type} '${body.resource}' for confidential or restricted data`);
    }
    const g: Grant = {
      id: nextGrantId(),
      subject_type: body.subject_type,
      subject,
      resource_type: body.resource_type,
      resource: body.resource,
      effect,
      constraints: {
        data_classes: body.constraints?.data_classes ?? null,
        budget_share: body.constraints?.budget_share ?? null,
        preset: body.constraints?.preset ?? null,
      },
      expires_at: body.expires_at ?? null,
      reason: body.reason.trim(),
      created_by: MOCK_USER,
      created_at: new Date().toISOString(),
      revoked_at: null,
      revoked_by: null,
      active: true,
    };
    grants.items.unshift(g);
    recordGrantChange(g, "create", MOCK_USER, g.reason);
    return HttpResponse.json(g, { status: 201 });
  }),

  http.delete(adminPath("/grants/:id"), ({ params, request }) => {
    const reason = queryOf(request).get("reason")?.trim() ?? "";
    if (reason.length < 3) return problem(422, "reason must be at least 3 characters");
    const g = grants.items.find((x) => x.id === params.id);
    if (!g) return problem(404, "grant not found");
    if (g.revoked_at) return problem(409, "grant is already revoked");
    g.revoked_at = new Date().toISOString();
    g.revoked_by = MOCK_USER;
    refreshActive(g);
    recordGrantChange(g, "revoke", MOCK_USER, reason);
    return HttpResponse.json(g);
  }),
];
