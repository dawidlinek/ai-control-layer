"use client";

import * as React from "react";
import { useGroups, useUsers } from "@/features/users/api";
import type { Directory } from "./model";

/** Names, groups and group budgets used to describe grants ("Jan Kowalski", "of developers 5.00"). */
export function useDirectory() {
  const users = useUsers();
  const groups = useGroups();
  const dir = React.useMemo<Directory>(
    () => ({
      names: new Map((users.data ?? []).map((u) => [u.username, u.display_name ?? u.username])),
      groupOf: new Map((users.data ?? []).filter((u) => u.groups[0]).map((u) => [u.username, u.groups[0]])),
      budgets: new Map((groups.data ?? []).map((g) => [g.name, g.settings?.daily_budget_usd ?? null])),
    }),
    [users.data, groups.data],
  );
  const subjects = React.useMemo(
    () => [
      ...(users.data ?? [])
        .filter((u) => u.kind === "user")
        .map((u) => ({ value: `user:${u.username}`, label: `${u.display_name ?? u.username} (${u.username})` })),
      ...(groups.data ?? []).map((g) => ({ value: `group:${g.name}`, label: `group ${g.name}` })),
    ],
    [users.data, groups.data],
  );
  return { dir, subjects, users, groups };
}
