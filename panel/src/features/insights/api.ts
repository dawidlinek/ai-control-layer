"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";
import type { InsightCluster } from "@/lib/api/types";

export const insightKeys = {
  clusters: [...queryKeys.insights.all, "clusters"] as const,
};

/** `/admin/v1/insights/clusters`: repeated tasks found in masked prompts (k-anonymity is applied by the gateway). */
export function useInsightClusters() {
  return useQuery({
    queryKey: insightKeys.clusters,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/insights/clusters", { signal })),
  });
}

export interface PublishInput {
  cluster: InsightCluster;
  skillId: string;
  model: string;
  preset: "monitor" | "balanced" | "strict" | "paranoid";
}

/**
 * Publish a draft skill for the cluster's group. Publishing changes the policy, so afterwards the live policy
 * version is read back for the "Saved as policy vN" line (the publish response is the cluster only).
 */
export function usePublishSkill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ cluster, skillId, model, preset }: PublishInput) => {
      const published = unwrap(
        await api.POST("/admin/v1/insights/clusters/{cluster_id}/publish", {
          params: { path: { cluster_id: cluster.id } },
          body: {
            skill_id: skillId,
            model,
            preset,
            groups: [cluster.group],
            reason: `Published from Automation Insights (${cluster.id}: ${cluster.label})`,
          },
        }),
      );
      let version: string | null = null;
      try {
        version = unwrap(await api.GET("/admin/v1/policy")).version;
      } catch {
        /* the skill is published either way; the version line is left out */
      }
      return { cluster: published, version };
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.insights.all });
      void qc.invalidateQueries({ queryKey: queryKeys.policy.all });
    },
  });
}
