"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export function useFeedStatus() {
  return useQuery({
    queryKey: queryKeys.feed.all,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/feed", { signal })),
  });
}

export function useSyncFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => unwrap(await api.POST("/admin/v1/feed/sync")),
    onSuccess: (status) => {
      qc.setQueryData(queryKeys.feed.all, status);
      void qc.invalidateQueries({ queryKey: queryKeys.feed.all });
    },
  });
}

export function useArtifacts() {
  return useQuery({
    queryKey: queryKeys.artifacts.all,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/artifacts", { signal })),
  });
}

/**
 * Events of the last 24 hours (one high-limit page) for client-side counts: signature hits per rule id, tool calls.
 * The contract has no per-rule / per-tool counters (see the report's API gaps).
 */
export function useEvents24h() {
  return useQuery({
    queryKey: [...queryKeys.events.all, "last24h"] as const,
    queryFn: async ({ signal }) => {
      const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      return unwrap(await api.GET("/admin/v1/events", { params: { query: { since, limit: 1000 } }, signal }));
    },
    staleTime: 30_000,
  });
}
