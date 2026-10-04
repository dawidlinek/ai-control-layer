"use client";

import * as React from "react";
import { useQueryClient, type QueryKey } from "@tanstack/react-query";
import type { components } from "./schema";
import { queryKeys } from "./hooks";

type EventSummary = components["schemas"]["EventSummary"];

export interface EventStreamOptions {
  /** Server-side filters (`subject`, `action`). */
  params?: { subject?: string; action?: string };
  enabled?: boolean;
  /**
   * Query keys whose cached array data gets the new event prepended (for lists of `EventSummary`).
   * Default: none. Pass e.g. `[queryKeys.events.list(filters)]` for a Traffic list that is on page 1.
   */
  prependTo?: QueryKey[];
  /** Extra keys to invalidate on every event. */
  invalidate?: QueryKey[];
  onEvent?: (event: EventSummary) => void;
}

/**
 * Subscribe to `/admin/v1/events/stream` (SSE; each `data:` line is an EventSummary).
 * Prepends to the given list caches, invalidates incident / approval caches when such an event arrives,
 * and reconnects automatically (EventSource does that itself, sending Last-Event-ID).
 */
export function useEventStream({ params, enabled = true, prependTo, invalidate, onEvent }: EventStreamOptions = {}) {
  const qc = useQueryClient();
  const [connected, setConnected] = React.useState(false);
  const handler = React.useRef({ prependTo, invalidate, onEvent });
  React.useEffect(() => {
    handler.current = { prependTo, invalidate, onEvent };
  });

  const qs = new URLSearchParams();
  if (params?.subject) qs.set("subject", params.subject);
  if (params?.action) qs.set("action", params.action);
  const url = `/admin/v1/events/stream${qs.size ? `?${qs}` : ""}`;

  React.useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    const source = new EventSource(url);
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (msg) => {
      let event: EventSummary;
      try {
        event = JSON.parse(msg.data) as EventSummary;
      } catch {
        return;
      }
      const h = handler.current;
      for (const key of h.prependTo ?? []) {
        qc.setQueryData<EventSummary[]>(key, (old) =>
          old && !old.some((e) => e.event_id === event.event_id) ? [event, ...old] : old,
        );
      }
      if (event.event_type === "incident") void qc.invalidateQueries({ queryKey: queryKeys.incidents.all });
      if (event.event_type === "approval") void qc.invalidateQueries({ queryKey: queryKeys.approvals.all });
      for (const key of h.invalidate ?? []) void qc.invalidateQueries({ queryKey: key });
      h.onEvent?.(event);
    };
    return () => {
      source.close();
      setConnected(false);
    };
  }, [enabled, url, qc]);

  return { connected };
}
