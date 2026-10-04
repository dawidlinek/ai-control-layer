import { HttpResponse } from "msw";

/** MSW path for an admin route, e.g. `adminPath("/incidents/:id")`. The `*` prefix matches any origin. */
export const adminPath = (path: string) => `*/admin/v1${path}`;

/** FastAPI-shaped error body (`{ "detail": ... }`). */
export function problem(status: number, detail: string) {
  return HttpResponse.json({ detail }, { status });
}

/** The signed-in demo user's username, used as author / decider / assignee in mutating handlers. */
export const MOCK_USER = "k.wojcik";

export function queryOf(request: Request): URLSearchParams {
  return new URL(request.url).searchParams;
}

/** Positive integer query param with a default and an upper bound. */
export function intParam(q: URLSearchParams, name: string, fallback: number, max = 1000): number {
  const n = Number(q.get(name));
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), max) : fallback;
}
