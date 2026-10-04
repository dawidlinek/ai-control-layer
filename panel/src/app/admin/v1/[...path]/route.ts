/**
 * Server-side proxy for the gateway admin API: `/admin/v1/*` -> `${ROGATKA_GATEWAY_URL}/admin/v1/*`.
 * Adds `Authorization: Bearer <access token from the Auth.js session>` (the browser never sees the token) and
 * streams the response body without buffering, so SSE (`text/event-stream`) works.
 * In mock mode the browser's MSW worker answers before a request ever reaches this handler.
 */
import type { NextRequest } from "next/server";
import { getAccessToken } from "@/lib/auth/server";
import { authMode } from "@/lib/auth/mode";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Hop-by-hop and identity headers that must not be forwarded to the gateway. */
const DROP_REQUEST = new Set(["host", "connection", "content-length", "cookie", "authorization", "accept-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"]);
/** The body is already decoded by fetch; length / encoding of the upstream no longer apply. */
const DROP_RESPONSE = new Set(["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "set-cookie"]);

function json(status: number, detail: string): Response {
  return Response.json({ detail }, { status });
}

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const base = process.env.ROGATKA_GATEWAY_URL;
  if (!base) return json(502, "ROGATKA_GATEWAY_URL is not configured");

  const token = await getAccessToken(req);
  if (!token && authMode() !== "dev") return json(401, "Not signed in");

  const { path } = await ctx.params;
  const target = new URL(`/admin/v1/${path.map(encodeURIComponent).join("/")}`, base);
  target.search = req.nextUrl.search;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (!DROP_REQUEST.has(key.toLowerCase())) headers.set(key, value);
  });
  if (token) headers.set("authorization", `Bearer ${token}`);

  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: req.method,
      headers,
      body: hasBody ? req.body : undefined,
      // Streaming request bodies need half-duplex in Node's fetch.
      ...(hasBody ? { duplex: "half" } : {}),
      redirect: "manual",
      cache: "no-store",
      signal: req.signal,
    } as RequestInit);
  } catch {
    return json(502, "Gateway unreachable");
  }

  const out = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!DROP_RESPONSE.has(key.toLowerCase())) out.set(key, value);
  });
  if (upstream.headers.get("content-type")?.includes("text/event-stream")) {
    out.set("cache-control", "no-cache, no-transform");
    out.set("x-accel-buffering", "no");
  }
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
export const HEAD = proxy;
export const OPTIONS = proxy;
