import createClient from "openapi-fetch";
import type { paths } from "./schema";
import type { Resp } from "./types";

/**
 * Typed client for the gateway admin API. Calls go to the panel's own origin (`/admin/v1/...`), where the
 * Next route handler `app/admin/v1/[...path]/route.ts` adds the bearer token and proxies to the gateway
 * (or MSW answers in mock mode). `baseUrl` is empty in the browser; tests set NEXT_PUBLIC_API_BASE_URL
 * because Node's fetch needs absolute URLs.
 */
export const api = createClient<paths>({
  baseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? "",
  // Resolve fetch at call time so MSW (which patches globalThis.fetch in tests) always sees the request.
  fetch: (request) => globalThis.fetch(request),
});

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly body: unknown;

  constructor(status: number, detail: string, body?: unknown) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

function detailOf(error: unknown, status: number): string {
  if (error && typeof error === "object" && "detail" in error) {
    const d = (error as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((x) => (x && typeof x === "object" && "msg" in x ? String((x as { msg: unknown }).msg) : String(x))).join("; ");
  }
  return `Request failed (${status})`;
}

type Result<T> = { data?: T; error?: unknown; response: Response };

/** Turn an openapi-fetch result into `data` or throw `ApiError` (so TanStack Query sees the failure). */
export function unwrap<T>(result: Result<T>): Resp<T> {
  if (result.error !== undefined || !result.response.ok) {
    throw new ApiError(result.response.status, detailOf(result.error, result.response.status), result.error);
  }
  return result.data as Resp<T>;
}
