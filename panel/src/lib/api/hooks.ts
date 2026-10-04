"use client";

import * as React from "react";
import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import type { components } from "./schema";
import { api, unwrap, unwrapWithTotal, type WithTotal } from "./client";

type S = components["schemas"];

/**
 * Query keys. Convention: `[domain, kind, ...params]`. Invalidate a whole domain with `[domain]`.
 * Screen agents add their keys in `features/<screen>/api.ts` following the same shape.
 */
export const queryKeys = {
  policy: { all: ["policy"] as const, status: ["policy", "status"] as const },
  events: {
    all: ["events"] as const,
    list: (params: object = {}) => ["events", "list", params] as const,
    trace: (id: string) => ["events", "trace", id] as const,
  },
  incidents: {
    all: ["incidents"] as const,
    list: (status?: string) => ["incidents", "list", status ?? "all"] as const,
    detail: (id: string) => ["incidents", "detail", id] as const,
  },
  approvals: {
    all: ["approvals"] as const,
    list: (status?: string) => ["approvals", "list", status ?? "all"] as const,
    detail: (id: string) => ["approvals", "detail", id] as const,
  },
  users: {
    all: ["users"] as const,
    list: (params: object = {}) => ["users", "list", params] as const,
    detail: (id: string) => ["users", "detail", id] as const,
  },
  groups: { all: ["groups"] as const },
  grants: { all: ["grants"] as const },
  models: { all: ["models"] as const },
  connectors: { all: ["connectors"] as const },
  tools: { all: ["tools"] as const },
  feed: {
    all: ["feed"] as const,
    signatures: (params: object = {}) => ["feed", "signatures", params] as const,
  },
  artifacts: { all: ["artifacts"] as const },
  budgets: { all: ["budgets"] as const },
  overview: { all: ["overview"] as const },
  /** Sidebar badge numbers (`/metrics/counts`). Refreshed whenever an incidents / approvals query is invalidated. */
  counts: ["counts"] as const,
  insights: { all: ["insights"] as const },
  sessions: { transcript: (id: string) => ["sessions", "transcript", id] as const },
};

export function usePolicyStatus() {
  return useQuery({
    queryKey: queryKeys.policy.status,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy", { signal })),
  });
}

/**
 * A list query whose cache entry is `{ items, total }` (total = `X-Total-Count`), exposed as the plain array in
 * `data` plus `total`: callers that only want the rows keep working, callers that show "N of M" read `total`.
 */
export type ListQuery<T> = Omit<UseQueryResult<WithTotal<T[]>>, "data"> & { data: T[] | undefined; total: number | undefined };

export function asList<T>(q: UseQueryResult<WithTotal<T[]>>): ListQuery<T> {
  return { ...q, data: q.data?.items, total: q.data?.total };
}

export function useIncidents(status?: string) {
  return asList(
    useQuery({
      queryKey: queryKeys.incidents.list(status),
      queryFn: async ({ signal }) =>
        unwrapWithTotal(await api.GET("/admin/v1/incidents", { params: { query: { status, limit: 200 } }, signal })),
    }),
  );
}

export function useApprovals(status?: S["ApprovalStatus"]) {
  return asList(
    useQuery({
      queryKey: queryKeys.approvals.list(status),
      queryFn: async ({ signal }) =>
        unwrapWithTotal(await api.GET("/admin/v1/approvals", { params: { query: { status } }, signal })),
    }),
  );
}

/**
 * Sidebar badges from `GET /metrics/counts`: "open incidents" = status open or triaged, "approvals" = pending (expired
 * ones not counted). The query is refetched when anything invalidates the incidents / approvals caches (mutations,
 * SSE events), so screens keep invalidating those keys as before; it also polls every 30 s as a backstop.
 */
export function useNavCounts() {
  const qc = useQueryClient();
  React.useEffect(
    () =>
      qc.getQueryCache().subscribe((event) => {
        if (event.type !== "updated" || event.action.type !== "invalidate") return;
        const domain = event.query.queryKey[0];
        if (domain === "incidents" || domain === "approvals") void qc.invalidateQueries({ queryKey: queryKeys.counts });
      }),
    [qc],
  );
  const counts = useQuery({
    queryKey: queryKeys.counts,
    refetchInterval: 30_000,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/metrics/counts", { signal })),
  });
  return {
    incidents: counts.data?.open_incidents,
    approvals: counts.data?.pending_approvals,
    quarantinedTools: counts.data?.quarantined_tools,
  };
}
