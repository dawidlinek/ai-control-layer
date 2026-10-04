"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export { usePolicyStatus } from "@/lib/api/hooks";

const P = queryKeys.policy.all;
export const policyKeys = {
  files: [...P, "files"] as const,
  file: (name: string) => [...P, "file", name] as const,
  schema: [...P, "schema"] as const,
  versions: [...P, "versions"] as const,
  version: (id: number) => [...P, "version", id] as const,
  dryRun: (params: object) => [...P, "dry-run", params] as const,
  hits: [...queryKeys.overview.all, "rule-hits", "24h"] as const,
};

export function usePolicyFiles() {
  return useQuery({
    queryKey: policyKeys.files,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy/files", { signal })),
  });
}

export function usePolicyFile(name: string | null) {
  return useQuery({
    queryKey: policyKeys.file(name ?? ""),
    enabled: !!name,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy/files/{name}", { params: { path: { name: name! } }, signal })),
  });
}

export function usePolicySchema() {
  return useQuery({
    queryKey: policyKeys.schema,
    staleTime: Infinity,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy/schema", { signal })),
  });
}

export function usePolicyVersions() {
  return useQuery({
    queryKey: policyKeys.versions,
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/policy/versions", { params: { query: { limit: 200 } }, signal })),
  });
}

export function usePolicyVersion(id: number | null) {
  return useQuery({
    queryKey: policyKeys.version(id ?? -1),
    enabled: id !== null,
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/policy/versions/{version_id}", { params: { path: { version_id: id! } }, signal })),
  });
}

/**
 * Hits per rule in the last 24 h. The admin API has no per-rule endpoint; the Overview metrics carry `top_rules`
 * (rule id → count) for a window, so the Rules table reads those. Missing rules show "—".
 */
export function useRuleHits() {
  return useQuery({
    queryKey: policyKeys.hits,
    staleTime: 60_000,
    queryFn: async ({ signal }) => {
      const o = unwrap(await api.GET("/admin/v1/metrics/overview", { params: { query: { window: "24h" } }, signal }));
      return o.top_rules;
    },
  });
}

/** Dry-run of a candidate file (replay of the last 500 requests). Cached per candidate so stepping back is instant. */
export function useDryRun(file: string, content: string | null, enabled: boolean) {
  return useQuery({
    queryKey: policyKeys.dryRun({ file, content }),
    enabled: enabled && content !== null,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    queryFn: async ({ signal }) =>
      unwrap(await api.POST("/admin/v1/policy/dry-run", { body: { files: { [file]: content! }, last_n: 500 }, signal })),
  });
}

export function useValidatePolicy() {
  return useMutation({
    mutationFn: async (files: Record<string, string>) => unwrap(await api.POST("/admin/v1/policy/validate", { body: { files } })),
  });
}

/** Write one file (validate → write → reload → new version). 409 when `base_version` is stale. */
export function useWritePolicyFile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { name: string; content: string; baseVersion: string; message: string }) =>
      unwrap(
        await api.PUT("/admin/v1/policy/files/{name}", {
          params: { path: { name: v.name } },
          body: { content: v.content, base_version: v.baseVersion, message: v.message },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: P }),
  });
}

export function useRollbackPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.POST("/admin/v1/policy/versions/{version_id}/rollback", { params: { path: { version_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: P }),
  });
}
