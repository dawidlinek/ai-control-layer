"use client";

import * as React from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";
import { useEventStream } from "@/lib/api/sse";
import type { EventSummary } from "@/lib/api/types";
import { matchesFilters, serverParams, sinceFor, type NameOf, type TrafficFilters } from "./model";

/** How many events one request asks for while filling a page (client-side filters may drop some). */
export const FETCH_BATCH = 200;
/** Upper bound of requests per page, so a filter that matches nothing does not walk the whole audit log. */
const MAX_BATCHES = 10;

export interface TrafficPage {
  rows: EventSummary[];
  hasNext: boolean;
  /** `before_seq` for the next page. */
  nextCursor: number | null;
}

export function trafficKey(f: TrafficFilters, size: number, cursor: number | null, names: number) {
  return [...queryKeys.events.all, "traffic", { ...f, size, cursor, names }] as const;
}

/**
 * Fill one page: ask the events endpoint (newest first, `before_seq` cursor) with the filters it supports and
 * apply the rest client-side, fetching more batches until the page is full or the log is exhausted.
 */
async function fetchTrafficPage(
  f: TrafficFilters,
  size: number,
  cursor: number | null,
  nameOf: NameOf,
  signal: AbortSignal,
): Promise<TrafficPage> {
  const { range, ...server } = serverParams(f);
  const since = sinceFor(range);
  const acc: EventSummary[] = [];
  let before = cursor ?? undefined;
  let exhausted = false;
  for (let i = 0; i < MAX_BATCHES; i++) {
    const batch = unwrap(
      await api.GET("/admin/v1/events", {
        params: { query: { ...server, event_type: "decision", since, before_seq: before, limit: FETCH_BATCH } },
        signal,
      }),
    );
    acc.push(...batch.filter((e) => matchesFilters(e, f, nameOf)));
    if (batch.length < FETCH_BATCH) {
      exhausted = true;
      break;
    }
    if (acc.length > size) break;
    before = batch[batch.length - 1].seq;
  }
  const rows = acc.slice(0, size);
  return {
    rows,
    hasNext: acc.length > size || (!exhausted && rows.length > 0),
    nextCursor: rows.length ? rows[rows.length - 1].seq : null,
  };
}

export function useTrafficPage(f: TrafficFilters, size: number, cursor: number | null, people: People) {
  return useQuery({
    queryKey: trafficKey(f, size, cursor, people.count),
    queryFn: ({ signal }) => fetchTrafficPage(f, size, cursor, people.nameOf, signal),
    placeholderData: keepPreviousData,
  });
}

/**
 * New events from the SSE stream are prepended to the first page when they match the filters.
 * (No LIVE badge or pause: Traffic is a list of past requests that quietly stays current.)
 */
export function useTrafficStream(f: TrafficFilters, size: number, page: number, people: People) {
  const qc = useQueryClient();
  const key = trafficKey(f, size, null, people.count);
  useEventStream({
    enabled: page === 1,
    onEvent: (ev) => {
      // The audit log also carries policy_change / admin / incident events; Traffic lists decisions only.
      if (ev.event_type !== "decision") return;
      if (ev.timestamp < sinceFor(f.range) || !matchesFilters(ev as EventSummary, f, people.nameOf)) return;
      qc.setQueryData<TrafficPage>(key, (old) => {
        if (!old || old.rows.some((r) => r.event_id === ev.event_id)) return old;
        const rows = [ev as EventSummary, ...old.rows].slice(0, size);
        return { rows, hasNext: old.hasNext || old.rows.length >= size, nextCursor: rows[rows.length - 1].seq };
      });
    },
  });
}

export function useTrace(id: string | null) {
  return useQuery({
    queryKey: queryKeys.events.trace(id ?? ""),
    enabled: !!id,
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/events/{event_id}/trace", { params: { path: { event_id: id! } }, signal })),
  });
}

export interface People {
  nameOf: NameOf;
  options: { value: string; label: string }[];
  count: number;
}

/** Display names for usernames (the events carry usernames only) and the options of the Who filter. */
export function usePeople(): People {
  const q = useQuery({
    queryKey: [...queryKeys.users.all, "directory"],
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/users", { params: { query: { limit: 500 } }, signal })),
    staleTime: 5 * 60_000,
  });
  return React.useMemo(() => {
    const map = new Map<string, string>();
    for (const u of q.data ?? []) map.set(u.username, u.display_name ?? u.username);
    const options = [...(q.data ?? [])]
      .filter((u) => !u.disabled)
      .sort((a, b) => (a.kind === b.kind ? (a.display_name ?? a.username).localeCompare(b.display_name ?? b.username) : a.kind === "user" ? -1 : 1))
      .map((u) => ({ value: u.username, label: u.display_name ?? u.username }));
    return { nameOf: (u) => (u ? (map.get(u) ?? u) : "unknown"), options, count: map.size };
  }, [q.data]);
}
