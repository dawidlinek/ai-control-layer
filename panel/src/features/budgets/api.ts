"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export const budgetKeys = {
  tree: [...queryKeys.budgets.all, "tree"] as const,
};

/** `/admin/v1/budgets`: the whole budget tree (company, groups, people, agents, sessions) with breakers. */
export function useBudgetTree() {
  return useQuery({
    queryKey: budgetKeys.tree,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/budgets", { signal })),
  });
}

/** Close an open circuit breaker (`POST /budgets/breakers/{id}/reset`). Admin only (the gateway enforces it). */
export function useResetBreaker() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (breakerId: string) =>
      unwrap(await api.POST("/admin/v1/budgets/breakers/{breaker_id}/reset", { params: { path: { breaker_id: breakerId } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.budgets.all });
      void qc.invalidateQueries({ queryKey: queryKeys.overview.all });
    },
  });
}
