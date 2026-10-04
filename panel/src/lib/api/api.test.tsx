import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { pushMockEvent } from "@/mocks/handlers/events";
import { makeEvent } from "@/mocks/db/events";
import { ApiError, api, unwrap } from "./client";
import { queryKeys, useIncidents, useNavCounts, usePolicyStatus } from "./hooks";
import { useEventStream } from "./sse";
import type { EventSummary } from "./types";

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const W = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return { client, W };
}

describe("typed client", () => {
  it("calls the admin API through MSW and unwraps the data", async () => {
    const data = unwrap(await api.GET("/admin/v1/policy"));
    expect(data.version).toBe("v8");
    expect(data.source).toBe("file");
  });

  it("throws ApiError with the server's detail", async () => {
    const result = await api.GET("/admin/v1/incidents/{incident_id}", { params: { path: { incident_id: "nope" } } });
    expect(() => unwrap(result)).toThrow(ApiError);
    try {
      unwrap(result);
    } catch (e) {
      expect((e as ApiError).status).toBe(404);
      expect((e as ApiError).detail).toBe("incident not found");
    }
  });
});

describe("hooks", () => {
  it("usePolicyStatus", async () => {
    const { W } = wrapper();
    const { result } = renderHook(() => usePolicyStatus(), { wrapper: W });
    await waitFor(() => expect(result.current.data?.version).toBe("v8"));
  });

  it("useIncidents filters by status", async () => {
    const { W } = wrapper();
    const { result } = renderHook(() => useIncidents("resolved"), { wrapper: W });
    await waitFor(() => expect(result.current.data).toHaveLength(2));
  });

  it("useNavCounts: 7 open incidents (open + triaged), 3 pending approvals", async () => {
    const { W } = wrapper();
    const { result } = renderHook(() => useNavCounts(), { wrapper: W });
    await waitFor(() => expect(result.current).toEqual({ incidents: 7, approvals: 3 }));
  });

  it("surfaces errors", async () => {
    server.use(http.get(adminPath("/policy"), () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    const { W } = wrapper();
    const { result } = renderHook(() => usePolicyStatus(), { wrapper: W });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as ApiError).detail).toBe("boom");
  });
});

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  listeners = new Map<string, Array<(m: { data: string }) => void>>();
  closed = false;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
    queueMicrotask(() => this.onopen?.());
  }
  close() {
    this.closed = true;
  }
  addEventListener(name: string, fn: (m: { data: string }) => void) {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), fn]);
  }
  /** Like the gateway: a named `event: event` frame. */
  emit(e: unknown, name = "event") {
    for (const fn of this.listeners.get(name) ?? []) fn({ data: JSON.stringify(e) });
  }
}

describe("useEventStream", () => {
  it("subscribes, prepends events to list caches and invalidates incidents", async () => {
    FakeEventSource.instances = [];
    (globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;
    const { client, W } = wrapper();
    const key = queryKeys.events.list({});
    const first = makeEvent({ event_id: "evt_old", seq: 1, timestamp: new Date().toISOString() });
    client.setQueryData<EventSummary[]>(key, [first]);
    const invalidate = vi.spyOn(client, "invalidateQueries");

    const { result, unmount } = renderHook(() => useEventStream({ prependTo: [key], params: { action: "block" } }), { wrapper: W });
    await waitFor(() => expect(result.current.connected).toBe(true));
    const es = FakeEventSource.instances[0];
    expect(es.url).toBe("/admin/v1/events/stream?action=block");

    es.emit(makeEvent({ event_id: "evt_new", seq: 2, timestamp: new Date().toISOString() }));
    expect(client.getQueryData<EventSummary[]>(key)?.map((e) => e.event_id)).toEqual(["evt_new", "evt_old"]);
    // no duplicates
    es.emit(makeEvent({ event_id: "evt_new", seq: 2, timestamp: new Date().toISOString() }));
    expect(client.getQueryData<EventSummary[]>(key)).toHaveLength(2);

    es.emit(makeEvent({ event_id: "evt_inc", seq: 3, event_type: "incident", timestamp: new Date().toISOString() }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.incidents.all });

    unmount();
    expect(es.closed).toBe(true);
    delete (globalThis as unknown as { EventSource?: unknown }).EventSource;
  });

  it("the mock stream endpoint accepts a connection and pushMockEvent adds to the db", async () => {
    const res = await fetch("http://localhost:3000/admin/v1/events/stream");
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    expect(decoder.decode((await reader.read()).value)).toContain(": connected");
    pushMockEvent(makeEvent({ event_id: "evt_live", seq: 5000, timestamp: new Date().toISOString(), summary: "live" }));
    expect(decoder.decode((await reader.read()).value)).toContain('"event_id":"evt_live"');
    reader.releaseLock();
    const list = unwrap(await api.GET("/admin/v1/events", { params: { query: { limit: 1 } } }));
    expect(list[0].event_id).toBe("evt_live");
  });
});
