"use client";

import { useQuery } from "@tanstack/react-query";
import type { components } from "./schema";
import { api, unwrap } from "./client";

type S = components["schemas"];

/**
 * Query keys. Convention: `[domain, kind, ...params]`. Invalidate a whole domain with `[domain]`.
 * Screen agents add their keys in `features/<screen>/api.ts` following the same shape.
 */
export const queryKeys = {
  policy: { status: ["policy", "status"] as const },
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
};

export function usePolicyStatus() {
  return useQuery({
    queryKey: queryKeys.policy.status,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy", { signal })),
  });
}

export function useIncidents(status?: string) {
  return useQuery({
    queryKey: queryKeys.incidents.list(status),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/incidents", { params: { query: { status, limit: 200 } }, signal })),
  });
}

export function useApprovals(status?: S["ApprovalStatus"]) {
  return useQuery({
    queryKey: queryKeys.approvals.list(status),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/approvals", { params: { query: { status } }, signal })),
  });
}

/**
 * Sidebar badges. "Open incidents" = status open or triaged (not resolved / false_positive);
 * "Approvals" = pending. (The API has no count endpoint: see the API gaps in panel/ARCHITECTURE.md.)
 */
export function useNavCounts() {
  const incidents = useIncidents();
  const approvals = useApprovals("pending");
  return {
    incidents: incidents.data?.filter((i) => i.status === "open" || i.status === "triaged").length,
    approvals: approvals.data?.length,
  };
}
