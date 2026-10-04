"use client";

import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export function useTranscript(id: string) {
  return useQuery({
    queryKey: queryKeys.sessions.transcript(id),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/sessions/{session_id}/transcript", { params: { path: { session_id: id } }, signal })),
  });
}
