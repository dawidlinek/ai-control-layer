/** MSW handlers: incidents (list, get, patch). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { incidents } from "../db/incidents";
import type { components } from "@/lib/api/schema";
import { adminPath, intParam, listResponse, MOCK_USER, problem, queryOf } from "./helpers";

type Patch = components["schemas"]["IncidentPatch"];

export const incidentsHandlers: HttpHandler[] = [
  http.get(adminPath("/incidents"), ({ request }) => {
    const q = queryOf(request);
    const status = q.get("status");
    const matching = incidents.items
      .filter((i) => (status ? i.status === status : true))
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return listResponse(matching.slice(0, intParam(q, "limit", 100)), matching.length);
  }),

  http.get(adminPath("/incidents/:id"), ({ params }) => {
    const i = incidents.items.find((x) => x.id === params.id);
    return i ? HttpResponse.json(i) : problem(404, "incident not found");
  }),

  http.patch(adminPath("/incidents/:id"), async ({ params, request }) => {
    const i = incidents.items.find((x) => x.id === params.id);
    if (!i) return problem(404, "incident not found");
    const body = (await request.json()) as Patch;
    const at = new Date().toISOString();
    if (body.status && body.status !== i.status) {
      i.notes.push({ author: MOCK_USER, at, text: `changed status to ${body.status}` });
      i.status = body.status;
    }
    if (body.assignee !== undefined && body.assignee !== i.assignee) {
      i.assignee = body.assignee;
      if (body.assignee) i.notes.push({ author: MOCK_USER, at, text: `assigned to ${body.assignee}` });
    }
    if (body.note) i.notes.push({ author: MOCK_USER, at, text: body.note });
    i.updated_at = at;
    return HttpResponse.json(i);
  }),
];
