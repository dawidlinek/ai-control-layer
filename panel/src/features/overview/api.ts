"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export const RANGES = ["15m", "1h", "24h", "7d"] as const;
export type Range = (typeof RANGES)[number];

/** `/admin/v1/metrics/overview?window=` (OverviewSummary). */
export function useOverview(window: Range) {
  return useQuery({
    queryKey: [...queryKeys.overview.all, "summary", window] as const,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/metrics/overview", { params: { query: { window } }, signal })),
  });
}

/** Latest decision events (for "Notable now"); the screen keeps the non-allow ones. */
export function useRecentDecisions(limit = 60) {
  return useQuery({
    queryKey: queryKeys.events.list({ event_type: "decision", limit, view: "overview" }),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/events", { params: { query: { event_type: "decision", limit } }, signal })),
  });
}

/**
 * username -> display name ("a.nowak" -> "Anna Nowak"). Events and budget nodes carry usernames only;
 * falls back to the username while loading or when the person is unknown.
 */
export function useDisplayNames(): (username: string | null | undefined) => string {
  const users = useQuery({
    queryKey: queryKeys.users.list({ limit: 500 }),
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/users", { params: { query: { limit: 500 } }, signal })),
    staleTime: 5 * 60_000,
  });
  const map = React.useMemo(() => new Map((users.data ?? []).map((u) => [u.username, u.display_name ?? u.username])), [users.data]);
  return React.useCallback((username) => (username ? (map.get(username) ?? username) : "someone"), [map]);
}
