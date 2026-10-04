"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys, useApprovals } from "@/lib/api/hooks";
import type { Approval, User } from "@/lib/api/types";

/** Every approval (all statuses); tabs and filters are applied client-side (the contract has no totals). */
export function useAllApprovals() {
  return useApprovals();
}

export interface DecideInput {
  id: string;
  decision: "approve" | "deny";
  /** Time-boxed elevation; omitted = approve once. */
  elevationMinutes?: number;
  note?: string;
}

export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: DecideInput): Promise<Approval> =>
      unwrap(
        await api.POST("/admin/v1/approvals/{approval_id}/decision", {
          params: { path: { approval_id: v.id } },
          body: { decision: v.decision, elevation_minutes: v.elevationMinutes ?? null, note: v.note?.trim() || null },
        }),
      ),
    // Refresh the list, the sidebar badge (pending count) and the access pages (elevations).
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.approvals.all });
      void qc.invalidateQueries({ queryKey: queryKeys.users.all });
    },
  });
}

/** Display names and kinds for usernames (Who column). Falls back to the username when the lookup fails. */
export function usePeople() {
  return useQuery({
    queryKey: [...queryKeys.users.all, "lookup"] as const,
    staleTime: 5 * 60_000,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/users", { params: { query: { limit: 500 } }, signal })),
    select: (users: User[]) => new Map(users.map((u) => [u.username, u])),
  });
}
