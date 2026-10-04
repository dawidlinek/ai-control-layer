"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export function useMcpServers() {
  return useQuery({
    queryKey: [...queryKeys.tools.all, "servers"] as const,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/mcp/servers", { signal })),
  });
}

export function useMcpTools() {
  return useQuery({
    queryKey: [...queryKeys.tools.all, "list"] as const,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/mcp/tools", { signal })),
  });
}

/** Re-pin a drifted / pending tool to its current hash (admin). */
export function useApproveTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { id: string; reason: string }) =>
      unwrap(
        await api.POST("/admin/v1/mcp/tools/{tool_id}/approve", {
          params: { path: { tool_id: v.id } },
          body: { reason: v.reason },
        }),
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.tools.all }),
  });
}

/** Quarantine a tool, or record the decision to keep it quarantined (analyst and up). */
export function useQuarantineTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { id: string; reason: string }) =>
      unwrap(
        await api.POST("/admin/v1/mcp/tools/{tool_id}/quarantine", {
          params: { path: { tool_id: v.id } },
          body: { reason: v.reason },
        }),
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.tools.all });
      void qc.invalidateQueries({ queryKey: queryKeys.incidents.all });
    },
  });
}
