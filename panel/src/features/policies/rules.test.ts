import { describe, expect, it } from "vitest";
import { currentFiles } from "@/mocks/db/policy";
import { impactSentence, liveSentence, parseDiff, suiteOf, versionLabel } from "./helpers";
import { deriveRules, lockedLines, readInjectionThreshold, readSessionThreshold, withInjectionThreshold, withSessionThreshold } from "./rules";
import { parseYaml, parseYamlWithLines, YamlError } from "./yaml-lite";
import { checkPolicyYaml, checkSchema } from "./schema-check";
import { POLICY_SCHEMA } from "@/mocks/handlers/policy";
import type { DryRunResponse, PolicyStatus, PolicyVersion } from "@/lib/api/types";

describe("yaml-lite", () => {
  it("parses block maps, sequences, flow collections, quotes and comments", () => {
    const v = parseYaml(`# comment
a: 1            # trailing
b: "x # not a comment"
c: [x, 'y', {k: v, n: [1, 2]}]
list:
  - id: SEC-PII-01
    stages: [ingress]
    params:
      entities: [PESEL]
  - plain
same_indent:
- one
- two
folded: >-
  first
  second
`);
    expect(v).toEqual({
      a: 1,
      b: "x # not a comment",
      c: ["x", "y", { k: "v", n: [1, 2] }],
      list: [{ id: "SEC-PII-01", stages: ["ingress"], params: { entities: ["PESEL"] } }, "plain"],
      same_indent: ["one", "two"],
      folded: "first second",
    });
  });

  it("reports errors with the line", () => {
    const cases: [string, string, number][] = [
      ["a: 1\n  b: 2", "bad indentation", 2],
      ["a: b: c", "mapping values are not allowed here", 1],
      ["a: 1\na: 2", 'duplicate key "a"', 2],
      ["a: [1, 2", "flow sequence", 1],
      ["a: 'open", "unterminated quoted string", 1],
    ];
    for (const [src, msg, line] of cases) {
      let err: unknown;
      try {
        parseYaml(src);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(YamlError);
      expect((err as YamlError).message).toContain(msg);
      expect((err as YamlError).line).toBe(line);
    }
  });
});

describe("schema check as you type", () => {
  it("passes the demo files and reports problems with their lines", () => {
    for (const [name, text] of Object.entries(currentFiles())) expect([name, checkPolicyYaml(text, POLICY_SCHEMA)]).toEqual([name, []]);
    const bad = currentFiles()["controls.yaml"].replace("cost_tier: l1", "cost_tier: l9");
    const line = bad.split("\n").findIndex((l) => l.includes("cost_tier: l9")) + 1;
    expect(checkPolicyYaml(bad, POLICY_SCHEMA)).toEqual([
      { line, path: "controls.2.cost_tier", message: '"l9" is not one of: deterministic, similarity, l1, l2' },
    ]);
    expect(checkPolicyYaml("a: [1", POLICY_SCHEMA)[0]).toMatchObject({ line: 1, path: null });
  });

  it("supports $ref, anyOf with null, required, additionalProperties and patterns", () => {
    const schema = {
      $defs: { Id: { type: "string", pattern: "^[A-Z]+-\\d+$" } },
      type: "object",
      additionalProperties: false,
      required: ["id"],
      properties: { id: { $ref: "#/$defs/Id" }, n: { anyOf: [{ type: "integer", minimum: 1 }, { type: "null" }] } },
    };
    expect(checkSchema({ id: "AB-1", n: null }, schema)).toEqual([]);
    expect(checkSchema({ id: "x", n: 0, extra: 1 }, schema).map((p) => [p.path.join("."), p.message])).toEqual([
      ["id", '"x" does not match ^[A-Z]+-\\d+$'],
      ["n", "must be at least 1"],
      ["extra", 'unknown field "extra"'],
    ]);
    expect(checkSchema({}, schema)[0].message).toBe('missing required field "id"');
  });

  it("maps JSON paths to lines", () => {
    const { lines } = parseYamlWithLines("a:\n  list:\n    - id: X\n      k: 1\n");
    expect(lines.get("a.list.0")).toBe(3);
    expect(lines.get("a.list.0.k")).toBe(4);
  });
});

describe("rules", () => {
  const files = currentFiles();
  const rules = deriveRules({ controls: files["controls.yaml"], groups: files["groups.yaml"] }, ["LOCK-01", "LOCK-02"]);
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));

  it("derives actions, modes, locks and settings", () => {
    expect(byId["SEC-PII-01"]).toMatchObject({ action: "pseudonymise", mode: "enforce", locked: false, setting: null });
    expect(byId["SEC-SECRET-01"]).toMatchObject({ action: "block", locked: true, lockId: "LOCK-02", setting: null });
    expect(byId["SEC-PI-01"]).toMatchObject({ action: "block", setting: "injection_threshold", costTier: "l1" });
    expect(byId["SEC-SAFE-01"]).toMatchObject({ action: "monitor", mode: "monitor" });
    expect(byId["SEC-FLOW-01"].action).toBe("require_approval");
    expect(byId["SEC-SESSION-01"]).toMatchObject({ action: "route_local", setting: "session_threshold" });
    expect(byId["LOCK-01"]).toMatchObject({ action: "route_local", mode: "always", locked: true, file: "groups.yaml" });
    expect(byId["SEC-PI-01"].snippet[0].text).toContain("- id: SEC-PI-01");
  });

  it("reads and edits the settings in the YAML text, keeping comments", () => {
    const c = files["controls.yaml"];
    expect(readInjectionThreshold(c)).toEqual({ value: 0.8, preset: "balanced" });
    const next = withInjectionThreshold(c, "balanced", 0.85)!;
    expect(readInjectionThreshold(next)!.value).toBe(0.85);
    // The strict preset is untouched.
    expect(next).toContain("injection_threshold: 0.50");
    expect(readSessionThreshold(c)).toBe("confidential");
    const s = withSessionThreshold(c, "SEC-SESSION-01", "restricted")!;
    expect(readSessionThreshold(s)).toBe("restricted");
    expect(s).toContain("threshold: restricted        # confidential | restricted");
  });

  it("marks org-locked lines", () => {
    const g = files["groups.yaml"];
    const lines = lockedLines("groups.yaml", g, []);
    const text = g.split("\n");
    expect(text[lines[0] - 1]).toBe("org_locks:");
    expect(lines.map((n) => text[n - 1]).join("\n")).toContain("controls: [SEC-SECRET-01]");
    expect(lines.map((n) => text[n - 1]).join("\n")).not.toContain("groups:");
  });
});

describe("helpers", () => {
  const versions = [{ id: 8, version: "3f2a9c1b7d4e", created_at: new Date().toISOString(), author: "k.wojcik", source: "panel", message: "", files_changed: [] }] as PolicyVersion[];

  it("labels hash versions by their sequence id", () => {
    expect(versionLabel("v8")).toBe("v8");
    expect(versionLabel("3f2a9c1b7d4e", versions)).toBe("v8");
    expect(versionLabel("abcdef0123456")).toBe("abcdef01");
  });

  it("writes the live sentence per source", () => {
    const status = { version: "3f2a9c1b7d4e", loaded_at: new Date().toISOString(), source: "panel", files: [], last_error: [], locked_controls: [] } as PolicyStatus;
    expect(liveSentence(status, versions, "k.wojcik")).toBe("published from the panel just now by you");
    expect(liveSentence({ ...status, source: "file" }, versions, "k.wojcik")).toMatch(/^loaded \d\d:\d\d from the file \(edited on disk\)$/);
  });

  it("builds the impact sentence and reads the suite numbers", () => {
    const r = {
      candidate_version: "v9",
      evaluated: 500,
      changed: 3,
      transitions: { "block->allow": 3, "suite:asr_before": 2.1, "suite:asr_after": 3.5, "suite:fpr_before": 3.1, "suite:fpr_after": 1.4, "suite:tests_total": 144, "suite:tests_passed": 142 },
      samples: [],
      errors: [],
    } as DryRunResponse;
    expect(impactSentence(r)).toBe("Would have let through 3 of the last 500 requests that were blocked.");
    expect(suiteOf(r)).toEqual({ asrBefore: 2.1, asrAfter: 3.5, fprBefore: 3.1, fprAfter: 1.4, testsPassed: 142, testsTotal: 144 });
    expect(suiteOf({ ...r, transitions: { "block->allow": 3 } })).toBeNull();
    expect(impactSentence({ ...r, changed: 0, transitions: {} })).toBe("Would not have changed any of the last 500 requests.");
  });

  it("parses a unified diff", () => {
    const files = parseDiff("--- a/x.yaml\n+++ b/x.yaml\n@@ -1,2 +1,2 @@\n keep\n-old\n+new");
    expect(files).toEqual([
      {
        name: "x.yaml",
        lines: [
          { kind: "hunk", text: "@@ -1,2 +1,2 @@" },
          { kind: "ctx", text: "keep" },
          { kind: "del", text: "old" },
          { kind: "add", text: "new" },
        ],
      },
    ]);
  });
});
