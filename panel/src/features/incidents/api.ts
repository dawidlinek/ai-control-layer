"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys, useIncidents } from "@/lib/api/hooks";
import type { components } from "@/lib/api/schema";

type Patch = components["schemas"]["IncidentPatch"];

/** Every incident (all statuses, high limit); tabs, filters and search are client-side (no totals in the contract). */
export function useAllIncidents() {
  return useIncidents();
}

export function usePatchIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { id: string } & Patch) => {
      const { id, ...body } = v;
      return unwrap(await api.PATCH("/admin/v1/incidents/{incident_id}", { params: { path: { incident_id: id } }, body }));
    },
    // Also refreshes the sidebar badge (open incidents).
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.incidents.all }),
  });
}

export function useQuarantineTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { toolId: string; reason: string }) =>
      unwrap(
        await api.POST("/admin/v1/mcp/tools/{tool_id}/quarantine", {
          params: { path: { tool_id: v.toolId } },
          body: { reason: v.reason },
        }),
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.tools.all }),
  });
}

export function useApproveTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { toolId: string; reason: string }) =>
      unwrap(
        await api.POST("/admin/v1/mcp/tools/{tool_id}/approve", {
          params: { path: { tool_id: v.toolId } },
          body: { reason: v.reason },
        }),
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.tools.all }),
  });
}

export function useResetBreaker() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { breakerId: string }) =>
      unwrap(await api.POST("/admin/v1/budgets/breakers/{breaker_id}/reset", { params: { path: { breaker_id: v.breakerId } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.budgets.all }),
  });
}
