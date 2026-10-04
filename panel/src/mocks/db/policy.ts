/**
 * Mock data: policy status (the Policies screen agent extends this: files, versions, dry-run, rules).
 * Demo story (HANDOFF section 6): live v8 was loaded from an external edit of controls.yaml.
 */
import { demoClock } from "../time";
import { registerReset } from "./registry";
import type { PolicyStatus } from "./types";

function seedStatus(): PolicyStatus {
  const modified = demoClock("14:02:00");
  return {
    version: "v8",
    loaded_at: modified,
    source: "file",
    files: ["controls.yaml", "models.yaml", "groups.yaml", "tools.yaml", "budgets.yaml", "routing.yaml"].map((name, i) => ({
      name,
      version: `sha256:${(i + 1).toString(16).repeat(8)}`,
      size: 2048 + i * 311,
      modified_at: name === "controls.yaml" ? modified : demoClock("09:00:00"),
    })),
    last_error: [],
    locked_controls: ["LOCK-01", "LOCK-02"],
  };
}

/** Mutable on purpose: write handlers replace fields (e.g. `version` after a publish). */
export const policyStatus: PolicyStatus = seedStatus();

registerReset(() => {
  Object.assign(policyStatus, seedStatus());
});
