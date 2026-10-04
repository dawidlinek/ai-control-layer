/** MSW handlers: events, traces, session transcripts, SSE stream (Traffic domain). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { buildTrace, buildTranscript, events, toAuditEvent } from "../db/events";
import type { EventSummary } from "../db/types";
import { adminPath, intParam, problem, queryOf } from "./helpers";

const streams = new Set<ReadableStreamDefaultController<Uint8Array>>();
const encoder = new TextEncoder();

/** Add an event to the mock db and push it to every open `/events/stream` connection (tests, demos). */
export function pushMockEvent(event: EventSummary): void {
  events.items.unshift(event);
  const chunk = encoder.encode(`event: event\nid: ${event.seq}\ndata: ${JSON.stringify(event)}\n\n`);
  for (const c of streams) {
    try {
      c.enqueue(chunk);
    } catch {
      streams.delete(c);
    }
  }
}

function findEvent(id: string): EventSummary | undefined {
  return events.items.find((e) => e.event_id === id || e.trace_id === id);
}

export const eventsHandlers: HttpHandler[] = [
  http.get(adminPath("/events"), ({ request }) => {
    const q = queryOf(request);
    const since = q.get("since");
    const until = q.get("until");
    const before = q.get("before_seq");
    const action = q.get("action");
    const list = events.items
      .filter((e) => (since ? e.timestamp >= since : true))
      .filter((e) => (until ? e.timestamp <= until : true))
      .filter((e) => (before ? e.seq < Number(before) : true))
      .filter((e) => (q.get("subject") ? e.subject === q.get("subject") || e.username === q.get("subject") : true))
      .filter((e) => (q.get("group") ? e.groups.includes(q.get("group")!) : true))
      .filter((e) => (q.get("agent") ? e.agent_id === q.get("agent") : true))
      .filter((e) => (q.get("rule_id") ? e.rule_ids.includes(q.get("rule_id")!) : true))
      .filter((e) => (action ? e.action === action || e.applied.includes(action as never) : true))
      .filter((e) => (q.get("point") ? e.point === q.get("point") : true))
      .filter((e) => (q.get("event_type") ? e.event_type === q.get("event_type") : true))
      .sort((a, b) => b.seq - a.seq)
      .slice(0, intParam(q, "limit", 100));
    return HttpResponse.json(list);
  }),

  // Must come before `/events/:id`.
  http.get(adminPath("/events/stream"), ({ request }) => {
    let controller: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        controller = c;
        streams.add(c);
        c.enqueue(encoder.encode(": connected\n\n"));
      },
      cancel() {
        streams.delete(controller);
      },
    });
    request.signal.addEventListener("abort", () => {
      streams.delete(controller);
      try {
        controller.close();
      } catch {
        /* already closed */
      }
    });
    return new HttpResponse(stream, {
      headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform" },
    });
  }),

  http.get(adminPath("/events/:id/trace"), ({ params }) => {
    const e = findEvent(String(params.id));
    return e ? HttpResponse.json(buildTrace(e)) : problem(404, "event not found");
  }),

  http.get(adminPath("/events/:id"), ({ params }) => {
    const e = findEvent(String(params.id));
    return e ? HttpResponse.json(toAuditEvent(e)) : problem(404, "event not found");
  }),

  http.get(adminPath("/sessions/:id/transcript"), ({ params }) => {
    const t = buildTranscript(String(params.id));
    return t ? HttpResponse.json(t) : problem(404, "session not found");
  }),
];
