"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap, unwrapWithTotal } from "@/lib/api/client";
import { asList, queryKeys } from "@/lib/api/hooks";
import type { FeedRuleCreate, FeedTarget } from "@/lib/api/types";

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

export interface SignatureFilters {
  target?: FeedTarget;
  q?: string;
}

/** Signatures of the active bundle (+ the offline baseline), with `hits_24h` / `last_hit_at`; `total` = X-Total-Count. */
export function useSignatures(filters: SignatureFilters = {}) {
  const params = { target: filters.target, q: filters.q?.trim() || undefined };
  return asList(
    useQuery({
      queryKey: queryKeys.feed.signatures(params),
      queryFn: async ({ signal }) =>
        unwrapWithTotal(await api.GET("/admin/v1/feed/signatures", { params: { query: { ...params, limit: 500 } }, signal })),
    }),
  );
}

/** The latest decisions that cited a rule in the last 24 hours (the sidebar's "Recent hits"). */
export function useRuleHits(ruleId: string | null) {
  return useQuery({
    queryKey: [...queryKeys.events.all, "rule-hits", ruleId ?? ""] as const,
    enabled: !!ruleId,
    queryFn: async ({ signal }) => {
      const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      return unwrap(await api.GET("/admin/v1/events", { params: { query: { rule_id: ruleId!, since, limit: 5 } }, signal }));
    },
  });
}

/** Publish a rule on the feed server (admin). Refreshes the signatures list and the feed status bar. */
export function useAddFeedRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: FeedRuleCreate) => unwrap(await api.POST("/admin/v1/feed/rules", { body })),
    onSuccess: (created) => {
      qc.setQueryData(queryKeys.feed.all, created.feed);
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
