"use client";

import * as React from "react";
import { usePolicyFile, usePolicyStatus } from "./api";
import { deriveRules, type PolicyRule } from "./rules";

/** Rules from the live `controls.yaml` and `groups.yaml` (+ the status' locked controls). */
export function usePolicyRules() {
  const status = usePolicyStatus();
  const controls = usePolicyFile("controls.yaml");
  const groups = usePolicyFile("groups.yaml");
  const locked = status.data?.locked_controls;
  const rules = React.useMemo<PolicyRule[] | undefined>(
    () => (controls.data ? deriveRules({ controls: controls.data.content, groups: groups.data?.content }, locked ?? []) : undefined),
    [controls.data, groups.data, locked],
  );
  return {
    rules,
    controls,
    isPending: controls.isPending || status.isPending,
    error: controls.error ?? status.error,
    refetch: () => {
      void controls.refetch();
      void groups.refetch();
      void status.refetch();
    },
  };
}
