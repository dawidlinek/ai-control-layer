"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/lib/api/schema";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys, useApprovals } from "@/lib/api/hooks";

type GrantCreate = components["schemas"]["GrantCreate"];

export const grantKeys = {
  list: [...queryKeys.grants.all, "list"] as const,
  changes: (subject?: string) => [...queryKeys.grants.all, "changes", subject ?? "all"] as const,
};

/**
 * Every grant, live and ended. The API filters on `active` (default true) and has no "all" switch the typed client
 * can send, so this asks twice and merges (newest first).
 */
export function useGrants() {
  return useQuery({
    queryKey: grantKeys.list,
    queryFn: async ({ signal }) => {
      const [live, ended] = await Promise.all([
        api.GET("/admin/v1/grants", { params: { query: { active: true } }, signal }).then(unwrap),
        api.GET("/admin/v1/grants", { params: { query: { active: false } }, signal }).then(unwrap),
      ]);
      return [...live, ...ended].sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
  });
}

export function useGrantChanges(subject?: string) {
  return useQuery({
    queryKey: grantKeys.changes(subject),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/grants/changes", { params: { query: { subject, limit: 200 } }, signal })),
  });
}

/** Time-boxed elevations come from decided approvals (`Approval.elevation`), not from the grants table. */
export function useElevations() {
  const q = useApprovals("approved");
  return { ...q, data: q.data?.filter((a) => a.elevation) };
}

function useInvalidateAccess() {
  const qc = useQueryClient();
  return () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: queryKeys.grants.all }),
      // effective access and "their clients see" live under the users domain
      qc.invalidateQueries({ queryKey: queryKeys.users.all }),
    ]);
}

export function useCreateGrant() {
  const invalidate = useInvalidateAccess();
  return useMutation({
    mutationFn: async (body: GrantCreate) => unwrap(await api.POST("/admin/v1/grants", { body })),
    onSuccess: () => invalidate(),
  });
}

export function useRevokeGrant() {
  const invalidate = useInvalidateAccess();
  return useMutation({
    mutationFn: async (v: { id: string; reason: string }) =>
      unwrap(await api.DELETE("/admin/v1/grants/{grant_id}", { params: { path: { grant_id: v.id }, query: { reason: v.reason } } })),
    onSuccess: () => invalidate(),
  });
}
