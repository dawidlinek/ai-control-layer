"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";
import type { ConnectorStatus } from "@/lib/api/types";

export function useConnectors() {
  return useQuery({
    queryKey: queryKeys.connectors.all,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/connectors", { signal })),
  });
}

export function useModels() {
  return useQuery({
    queryKey: queryKeys.models.all,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/models", { signal })),
  });
}

export interface KillSwitchResult {
  connector: ConnectorStatus;
  /** New live policy version when the switch created one (the demo gateway does); null otherwise. */
  savedAs: string | null;
}

/**
 * Engage / release a connector's kill switch. Reads the live policy version before and after so the result can say
 * "Saved as policy v9" only when the gateway really created a version.
 */
export function useKillSwitch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { id: string; engaged: boolean; reason: string }): Promise<KillSwitchResult> => {
      const before = await api.GET("/admin/v1/policy").then((r) => (r.data ? r.data.version : null)).catch(() => null);
      const connector = unwrap(
        await api.POST("/admin/v1/connectors/{connector_id}/kill-switch", {
          params: { path: { connector_id: v.id } },
          body: { engaged: v.engaged, reason: v.reason },
        }),
      );
      const after = await api.GET("/admin/v1/policy").then((r) => (r.data ? r.data.version : null)).catch(() => null);
      return { connector, savedAs: after && after !== before ? after : null };
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.connectors.all });
      void qc.invalidateQueries({ queryKey: queryKeys.models.all });
      void qc.invalidateQueries({ queryKey: queryKeys.policy.all });
    },
  });
}
