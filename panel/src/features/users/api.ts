"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";
import type { GroupSettings } from "@/lib/api/types";

/** All principals (people + agents). The API has no totals: one high-limit list, filtered and paged client-side. */
export function useUsers() {
  return useQuery({
    queryKey: queryKeys.users.list({ limit: 1000 }),
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/users", { params: { query: { limit: 1000 } }, signal })),
  });
}

export function useGroups() {
  return useQuery({
    queryKey: [...queryKeys.groups.all, "list"],
    queryFn: async ({ signal }) => unwrap(await api.GET("/admin/v1/groups", { signal })),
  });
}

export function useEffectiveAccess(userId: string | null) {
  return useQuery({
    queryKey: [...queryKeys.users.all, "access", userId ?? ""],
    enabled: !!userId,
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/users/{user_id}/effective-access", { params: { path: { user_id: userId! } }, signal })),
  });
}

export function useUserActivity(userId: string | null, limit = 4) {
  return useQuery({
    queryKey: [...queryKeys.users.all, "activity", userId ?? "", limit],
    enabled: !!userId,
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/users/{user_id}/activity", { params: { path: { user_id: userId! }, query: { limit } }, signal })),
  });
}

/** Draft → validate → impact for a group's settings (writes nothing). Runs while the draft differs from the saved settings. */
export function useGroupPreview(name: string, settings: GroupSettings, baseVersion: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: [...queryKeys.groups.all, "preview", name, settings, baseVersion ?? ""],
    enabled: enabled && !!baseVersion,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }) =>
      unwrap(
        await api.POST("/admin/v1/groups/{name}/settings/preview", {
          params: { path: { name } },
          body: { settings, base_version: baseVersion!, message: "" },
          signal,
        }),
      ),
  });
}

/** Save group settings as a new policy version (returns the new PolicyStatus). */
export function useSaveGroupSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { name: string; settings: GroupSettings; baseVersion: string }) =>
      unwrap(
        await api.PUT("/admin/v1/groups/{name}/settings", {
          params: { path: { name: v.name } },
          body: { settings: v.settings, base_version: v.baseVersion, message: "" },
        }),
      ),
    onSuccess: (status) => {
      qc.setQueryData(queryKeys.policy.status, status);
      return Promise.all([
        qc.invalidateQueries({ queryKey: queryKeys.groups.all }),
        qc.invalidateQueries({ queryKey: queryKeys.users.all }),
        qc.invalidateQueries({ queryKey: queryKeys.policy.all }),
      ]);
    },
  });
}
