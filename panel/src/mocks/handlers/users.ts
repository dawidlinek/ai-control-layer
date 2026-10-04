/**
 * MSW handlers: users and groups (lookups only for now).
 * TODO (Users screen agent): effective access, API keys, break-glass, group settings preview/update
 * (see ../db/users.ts and UsersGroups.dc.html / UsersGroupsGroups.dc.html).
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import { events } from "../db/events";
import { findUser, groups, users } from "../db/users";
import { adminPath, intParam, problem, queryOf } from "./helpers";

export const usersHandlers: HttpHandler[] = [
  http.get(adminPath("/users"), ({ request }) => {
    const q = queryOf(request);
    const text = q.get("q")?.toLowerCase();
    const group = q.get("group");
    const list = users.items
      .filter((u) => (group ? u.groups.includes(group) : true))
      .filter((u) => (text ? [u.username, u.display_name, u.email].some((v) => v?.toLowerCase().includes(text)) : true))
      .slice(0, intParam(q, "limit", 100));
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/users/:id/activity"), ({ params, request }) => {
    const u = findUser(String(params.id));
    if (!u) return problem(404, "user not found");
    const limit = intParam(queryOf(request), "limit", 20);
    const list = events.items
      .filter((e) => e.subject === u.subject || e.username === u.username)
      .sort((a, b) => b.seq - a.seq)
      .slice(0, limit);
    return HttpResponse.json(list);
  }),

  http.get(adminPath("/users/:id"), ({ params }) => {
    const u = findUser(String(params.id));
    return u ? HttpResponse.json(u) : problem(404, "user not found");
  }),

  http.get(adminPath("/groups"), () => HttpResponse.json(groups.items)),

  http.get(adminPath("/groups/:name/detail"), ({ params }) => {
    const g = groups.items.find((x) => x.name === params.name);
    return g ? HttpResponse.json(g) : problem(404, "group not found");
  }),
];
