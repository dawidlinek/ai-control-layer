import { afterEach, describe, expect, it } from "vitest";
import { act, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { makeEvent } from "@/mocks/db/events";
import { pushMockEvent } from "@/mocks/handlers/events";
import { renderApp } from "@/test/render";
import { TrafficScreen } from "./traffic-screen";

/** Real gateway shape: the audit log also holds policy_change events, which have no subject / point / model. */
const now = Date.now();
const iso = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
const DECISION = makeEvent({
  event_id: "evt_real_dec",
  seq: 20,
  timestamp: iso(2),
  username: "a.nowak",
  subject: "a.nowak",
  point: "ingress",
  model: "gemini/flash",
  action: "allow",
  applied: ["allow"],
});
const POLICY_CHANGE = makeEvent({ event_id: "evt_real_policy", seq: 21, timestamp: iso(1), event_type: "policy_change" });

/**
 * EventSource stand-in that reads the (MSW) stream over fetch and dispatches frames by their `event:` name like a
 * browser does: a named frame never reaches `onmessage`, only listeners of that name.
 */
class StreamEventSource {
  static instances: StreamEventSource[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private listeners = new Map<string, Array<(m: { data: string }) => void>>();
  private ctrl = new AbortController();
  connected: Promise<void>;
  constructor(url: string) {
    StreamEventSource.instances.push(this);
    let resolve!: () => void;
    this.connected = new Promise((r) => (resolve = r));
    void (async () => {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL ?? ""}${url}`, { signal: this.ctrl.signal });
      resolve();
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        buf += dec.decode(value);
        let i: number;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const frame = buf.slice(0, i);
          buf = buf.slice(i + 2);
          let name = "message";
          const data: string[] = [];
          for (const line of frame.split("\n")) {
            if (line.startsWith("event:")) name = line.slice(6).trim();
            else if (line.startsWith("data:")) data.push(line.slice(5).trim());
          }
          if (data.length) for (const fn of this.listeners.get(name) ?? []) fn({ data: data.join("\n") });
        }
      }
    })().catch(() => undefined);
  }
  addEventListener(name: string, fn: (m: { data: string }) => void) {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), fn]);
  }
  close() {
    this.ctrl.abort();
  }
}

afterEach(() => {
  delete (globalThis as unknown as { EventSource?: unknown }).EventSource;
  StreamEventSource.instances.forEach((e) => e.close());
  StreamEventSource.instances = [];
});

function useRealEvents(seen: string[] = []) {
  server.use(
    http.get(adminPath("/events"), ({ request }) => {
      seen.push(new URL(request.url).search);
      const type = new URL(request.url).searchParams.get("event_type");
      const all = [POLICY_CHANGE, DECISION];
      return HttpResponse.json(type ? all.filter((e) => e.event_type === type) : all);
    }),
  );
  return seen;
}

describe("Traffic against the real gateway shape", () => {
  it("asks for decision events only, so policy_change rows never show up as blank lines", async () => {
    const seen = useRealEvents();
    renderApp(<TrafficScreen />, { pathname: "/traffic", urlMemory: true });
    await waitFor(() => expect(document.querySelector('[data-row-id="evt_real_dec"]')).not.toBeNull());
    expect(document.querySelector('[data-row-id="evt_real_policy"]')).toBeNull();
    expect(seen.length).toBeGreaterThan(0);
    for (const qs of seen) expect(new URLSearchParams(qs).get("event_type")).toBe("decision");
  });

  it("shows live decisions on page 1 for the filters in the URL, ignoring other events and duplicates", async () => {
    (globalThis as unknown as { EventSource: unknown }).EventSource = StreamEventSource;
    renderApp(<TrafficScreen />, { pathname: "/traffic", searchParams: "?who=a.nowak&point=ingress&decision=block", urlMemory: true });
    await waitFor(() => expect(screen.getByRole("table", { name: "Events" })).toBeInTheDocument());
    await waitFor(() => expect(StreamEventSource.instances.length).toBeGreaterThan(0));
    await StreamEventSource.instances[0]!.connected;
    const base = { timestamp: iso(0), username: "a.nowak", subject: "a.nowak", point: "ingress" as const };
    const block = { ...base, action: "block" as const, applied: ["block" as const] };

    act(() => pushMockEvent(makeEvent({ event_id: "evt_live_policy", seq: 9001, ...base, event_type: "policy_change" })));
    act(() => pushMockEvent(makeEvent({ event_id: "evt_live_other_user", seq: 9002, ...block, username: "j.kowalski", subject: "j.kowalski" })));
    act(() => pushMockEvent(makeEvent({ event_id: "evt_live_allow", seq: 9003, ...base, action: "allow", applied: ["allow"] })));
    act(() => pushMockEvent(makeEvent({ event_id: "evt_live_block", seq: 9004, ...block })));
    await waitFor(() => expect(document.querySelector('[data-row-id="evt_live_block"]')).not.toBeNull());
    act(() => pushMockEvent(makeEvent({ event_id: "evt_live_block", seq: 9004, ...block })));
    for (const id of ["evt_live_policy", "evt_live_other_user", "evt_live_allow"]) {
      expect(document.querySelector(`[data-row-id="${id}"]`)).toBeNull();
    }
    expect(document.querySelectorAll('[data-row-id="evt_live_block"]')).toHaveLength(1);
    // newest first
    const ids = [...document.querySelectorAll("[data-row-id]")].map((r) => r.getAttribute("data-row-id"));
    expect(ids[0]).toBe("evt_live_block");
  });
});
