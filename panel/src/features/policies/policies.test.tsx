import * as React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { renderApp } from "@/test/render";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { currentFiles, policyDb, simulateDiskEdit } from "@/mocks/db/policy";
import { DEV_USER } from "@/lib/auth/user";
import type { YamlEditorProps } from "./yaml-editor";
import { PoliciesScreen } from "./policies-screen";

// Monaco cannot run in jsdom: a textarea stands in for the editor and exposes the decorations as data attributes.
vi.mock("./yaml-editor", () => ({
  YamlEditor: (p: YamlEditorProps) => (
    <textarea
      aria-label={p.ariaLabel}
      value={p.value}
      readOnly={p.readOnly}
      data-highlight-line={p.highlightLine ?? ""}
      data-locked-lines={(p.lockedLines ?? []).join(",")}
      data-markers={(p.errors ?? []).map((e) => e.line).join(",")}
      onChange={(e) => p.onChange(e.target.value)}
    />
  ),
}));

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"], title: undefined };
const ANALYST = { ...DEV_USER, role: "analyst" as const, roles: ["acl-analyst"], title: undefined };

beforeEach(() => {
  // Hits come from the Overview metrics (`top_rules`); the prototype's numbers.
  server.use(
    http.get(adminPath("/metrics/overview"), () =>
      HttpResponse.json({ top_rules: { "SEC-PII-01": 128, "SEC-SECRET-01": 6, "SEC-PI-01": 41, "SEC-SAFE-01": 12, "SEC-EXFIL-01": 0, "SEC-FLOW-01": 3, "SEC-MCP-01": 1, "LOCK-01": 64 } }),
    ),
  );
});

const live = () => screen.getByTestId("policy-live");
const sidebar = () => screen.getByRole("complementary", { name: "Rule" });

describe("Policies: header and Rules", () => {
  it("shows the live version from the status and the rules from the files", async () => {
    renderApp(<PoliciesScreen />, { pathname: "/policies" });
    expect(screen.getByRole("heading", { level: 1, name: "Policies" })).toBeInTheDocument();
    await waitFor(() => expect(live()).toHaveTextContent(/^live v8 · loaded \d\d:\d\d from the file \(edited on disk\)$/));
    const table = await screen.findByRole("table", { name: "Rules" });
    const pi = (await within(table).findByText("SEC-PI-01")).closest("tr")!;
    expect(pi).toHaveTextContent("Blocks prompts and tool results that look like an injection.");
    expect(within(pi).getByText("block")).toBeInTheDocument();
    expect(pi).toHaveTextContent("enforce");
    await waitFor(() => expect(pi).toHaveTextContent("41"));
    const secret = within(table).getByText("SEC-SECRET-01").closest("tr")!;
    expect(within(secret).getByRole("img", { name: "Org lock" })).toBeInTheDocument();
    const safe = within(table).getByText("SEC-SAFE-01").closest("tr")!;
    expect(safe).toHaveTextContent("monitor");
    const lock = within(table).getByText("LOCK-01").closest("tr")!;
    expect(lock).toHaveTextContent("always");
    expect(within(lock).getByText("route_local")).toBeInTheDocument();
    expect(within(table).getByText("SEC-SESSION-01")).toBeInTheDocument();
    expect(screen.getByText("files: controls · models · groups · tools · budgets · routing")).toBeInTheDocument();
  });

  it("filters rules by the search text and opens a rule from the URL", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-PII-01" });
    expect(await within(await screen.findByRole("complementary", { name: "Rule" })).findByText(/replaced with placeholders/)).toBeInTheDocument();
    await user.type(screen.getByRole("searchbox", { name: "Search rules" }), "injection");
    const table = screen.getByRole("table", { name: "Rules" });
    await waitFor(() => expect(within(table).queryByText("SEC-PII-01")).not.toBeInTheDocument());
    expect(within(table).getByText("SEC-PI-01")).toBeInTheDocument();
    // The selected rule was filtered out: the sidebar closes.
    expect(screen.queryByRole("complementary", { name: "Rule" })).not.toBeInTheDocument();
  });

  it("shows the rule's YAML lines and links to its hits in Traffic", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-FLOW-01" });
    const pre = await within(await screen.findByRole("complementary", { name: "Rule" })).findByLabelText("SEC-FLOW-01 in controls.yaml");
    expect(pre).toHaveTextContent("- id: SEC-FLOW-01");
    expect(pre).toHaveTextContent("type: rule_of_two");
    expect(within(sidebar()).getByRole("link", { name: "See its hits in Traffic" })).toHaveAttribute("href", "/traffic?rule=SEC-FLOW-01");
    expect(within(sidebar()).getByText("require_approval")).toBeInTheDocument();
  });
});

describe("Policies: changing a setting", () => {
  it("threshold change → dry-run impact → publish → v9 is live and the header updates", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-PI-01" });
    await within(await screen.findByRole("complementary", { name: "Rule" })).findByText("Block when the injection score is at least");
    expect(screen.getByLabelText("Injection threshold")).toHaveTextContent("0.80");
    expect(sidebar()).toHaveTextContent("live 0.80 · preset balanced");

    await user.click(screen.getByRole("button", { name: "Raise" }));
    expect(screen.getByLabelText("Injection threshold")).toHaveTextContent("0.85");
    const box = await screen.findByRole("form", { name: "If you publish this" });
    expect(await within(box).findByText("Would have let through 3 of the last 500 requests that were blocked.")).toBeInTheDocument();
    expect(box).toHaveTextContent("2.1% → 3.5%");
    expect(box).toHaveTextContent("3.1% → 1.4%");
    expect(box).toHaveTextContent("142 / 144 pass · 2 known attacks now get through");

    // The note is required.
    await user.click(within(box).getByRole("button", { name: "Publish as v9" }));
    expect(await within(box).findByRole("alert")).toHaveTextContent("Write a short note for the history.");
    expect(policyDb.versions).toHaveLength(8);

    await user.type(within(box).getByRole("textbox", { name: "Note for history" }), "Fewer false alarms for developers");
    await user.click(within(box).getByRole("button", { name: "Publish as v9" }));

    expect(await within(sidebar()).findByText("v9 is live")).toBeInTheDocument();
    expect(sidebar()).toHaveTextContent("Saved as policy v9 · new requests use it now.");
    await waitFor(() => expect(live()).toHaveTextContent("live v9 · published from the panel just now by you"));
    expect(screen.queryByRole("form", { name: "If you publish this" })).not.toBeInTheDocument();
    await waitFor(() => expect(sidebar()).toHaveTextContent("live 0.85 · preset balanced"));

    const v9 = policyDb.versions.at(-1)!;
    expect(v9).toMatchObject({ version: "v9", source: "panel", author: "k.wojcik", message: "Fewer false alarms for developers", files_changed: ["controls.yaml"] });
    expect(currentFiles()["controls.yaml"]).toContain("injection_threshold: 0.85");
  });

  it("discard drops the change without publishing", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-PI-01" });
    await within(await screen.findByRole("complementary", { name: "Rule" })).findByText("Block when the injection score is at least");
    await user.click(screen.getByRole("button", { name: "Lower" }));
    const box = await screen.findByRole("form", { name: "If you publish this" });
    expect(await within(box).findByText("Would have blocked 6 more of the last 500 requests.")).toBeInTheDocument();
    await user.click(within(box).getByRole("button", { name: "Discard" }));
    expect(screen.queryByRole("form", { name: "If you publish this" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Injection threshold")).toHaveTextContent("0.80");
    expect(policyDb.versions).toHaveLength(8);
    expect(live()).toHaveTextContent("live v8");
  });

  it("SEC-SESSION-01 has its threshold setting (confidential / restricted)", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-SESSION-01" });
    const group = await within(await screen.findByRole("complementary", { name: "Rule" })).findByRole("group", { name: "Session threshold" });
    expect(within(group).getByRole("button", { name: "confidential" })).toHaveAttribute("aria-pressed", "true");
    await user.click(within(group).getByRole("button", { name: "restricted" }));
    const box = await screen.findByRole("form", { name: "If you publish this" });
    expect(await within(box).findByText(/9 of the last 500 requests would have gone to a cloud model instead of staying local\./)).toBeInTheDocument();
    await user.type(within(box).getByRole("textbox", { name: "Note for history" }), "Only restricted sessions stay local");
    await user.click(within(box).getByRole("button", { name: "Publish as v9" }));
    expect(await within(sidebar()).findByText("v9 is live")).toBeInTheDocument();
    expect(currentFiles()["controls.yaml"]).toMatch(/threshold: restricted\s+# confidential \| restricted/);
  });

  it("shows the conflict when the file changed before publishing", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-PI-01" });
    await within(await screen.findByRole("complementary", { name: "Rule" })).findByText("Block when the injection score is at least");
    await user.click(screen.getByRole("button", { name: "Raise" }));
    const box = await screen.findByRole("form", { name: "If you publish this" });
    await within(box).findByText(/Would have let through 3/);
    simulateDiskEdit("controls.yaml", currentFiles()["controls.yaml"].replace("poll_s: 30", "poll_s: 60"));
    await user.type(within(box).getByRole("textbox", { name: "Note for history" }), "Raise");
    await user.click(within(box).getByRole("button", { name: "Publish as v9" }));
    expect(await within(box).findByText("controls.yaml changed since you opened it")).toBeInTheDocument();
    await user.click(within(box).getByRole("button", { name: "Reload and check again" }));
    await waitFor(() => expect(within(box).queryByText("controls.yaml changed since you opened it")).not.toBeInTheDocument());
  });

  it("org-locked rules are read-only", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-SECRET-01" });
    const side = await screen.findByRole("complementary", { name: "Rule" });
    expect(await within(side).findByText(/Org lock LOCK-02 — it can’t be changed or turned off here\. Changes go through the file with a review\./)).toBeInTheDocument();
    expect(within(side).queryByRole("heading", { name: "Setting" })).not.toBeInTheDocument();
    expect(within(side).queryByRole("button", { name: "Raise" })).not.toBeInTheDocument();
  });

  it("viewers read the setting but cannot change or publish it", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-PI-01", user: VIEWER });
    const side = await screen.findByRole("complementary", { name: "Rule" });
    await within(side).findByText("Block when the injection score is at least");
    expect(within(side).getByRole("button", { name: "Raise" })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "Lower" })).toBeDisabled();
    expect(within(side).getByText(/Only admins can change policy/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Publish/ })).not.toBeInTheDocument();
  });
});

describe("Policies: YAML", () => {
  it("opens the rule's file with its line highlighted and org-lock lines marked", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?rule=SEC-SECRET-01" });
    const side = await screen.findByRole("complementary", { name: "Rule" });
    await user.click(await within(side).findByRole("button", { name: "Open in YAML" }));
    const editor = await screen.findByRole("textbox", { name: "controls.yaml editor" });
    const lines = (editor as HTMLTextAreaElement).value.split("\n");
    const idLine = lines.findIndex((l) => l.includes("id: SEC-SECRET-01")) + 1;
    expect(editor).toHaveAttribute("data-highlight-line", String(idLine));
    expect(editor.getAttribute("data-locked-lines")!.split(",")).toContain(String(idLine));
    expect(screen.getByRole("tab", { name: "YAML" })).toHaveAttribute("aria-selected", "true");
  });

  it("switches files and marks the org locks in groups.yaml", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml" });
    await screen.findByRole("textbox", { name: "controls.yaml editor" });
    await user.click(await screen.findByRole("button", { name: "groups.yaml" }));
    const editor = await screen.findByRole("textbox", { name: "groups.yaml editor" });
    await waitFor(() => expect((editor as HTMLTextAreaElement).value).toContain("org_locks:"));
    expect(editor.getAttribute("data-locked-lines")).not.toBe("");
  });

  it("validate lists the errors", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml" });
    const editor = (await screen.findByRole("textbox", { name: "controls.yaml editor" })) as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toContain("SEC-PI-01"));
    await waitFor(() => expect(screen.getByTestId("typing-check")).toHaveTextContent("no problems"));
    fireEvent.change(editor, { target: { value: editor.value.replace("cost_tier: l1", "cost_tier: l9").replace("timeout_ms: 80", "timeout_ms: fast") } });
    expect(screen.getByText(/unsaved changes/)).toBeInTheDocument();
    // Checked against the schema as you type.
    await waitFor(() => expect(screen.getByTestId("typing-check")).toHaveTextContent("2 problems"));
    const typing = screen.getByRole("region", { name: "Problems as you type" });
    expect(typing).toHaveTextContent('"l9" is not one of: deterministic, similarity, l1, l2');
    expect(typing).toHaveTextContent("must be a whole number");
    await user.click(screen.getByRole("button", { name: "Validate" }));
    const box = await screen.findByRole("alert");
    expect(box).toHaveTextContent("2 problems in controls.yaml");
    const problems = within(box).getByRole("list", { name: "Problems" });
    expect(problems).toHaveTextContent("cost_tier must be one of deterministic, similarity, l1, l2");
    expect(problems).toHaveTextContent("timeout_ms must be a whole number from 1 to 60000");
    expect(editor.getAttribute("data-markers")!.split(",")).toHaveLength(2);
    // Jump to the line of an error.
    const jump = within(problems).getAllByRole("button")[0];
    await user.click(jump);
    expect(editor.getAttribute("data-highlight-line")).toBe(jump.textContent!.replace(/.*L/, ""));
  });

  it("validate reports YAML syntax errors with the line", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml" });
    const editor = (await screen.findByRole("textbox", { name: "controls.yaml editor" })) as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toContain("SEC-PI-01"));
    fireEvent.change(editor, { target: { value: editor.value.replace("  mode: enforce", "  mode: enforce: yes") } });
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("mapping values are not allowed here");
  });

  it("save creates a new version", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml" });
    const editor = (await screen.findByRole("textbox", { name: "controls.yaml editor" })) as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toContain("SEC-PI-01"));
    fireEvent.change(editor, { target: { value: editor.value.replace("poll_s: 30", "poll_s: 45") } });
    await user.click(screen.getByRole("button", { name: "Save as v9" }));
    expect(await screen.findByText("Write a short note for the history.")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Note for history" }), "Poll the feed less often");
    await user.click(screen.getByRole("button", { name: "Save as v9" }));
    expect(await screen.findByText("Saved as policy v9")).toBeInTheDocument();
    await waitFor(() => expect(live()).toHaveTextContent("live v9 · published from the panel just now by you"));
    expect(policyDb.versions.at(-1)!.message).toBe("Poll the feed less often");
  });

  it("409 conflict: someone saved a newer version; reload takes the latest file", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml" });
    const editor = (await screen.findByRole("textbox", { name: "controls.yaml editor" })) as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toContain("SEC-PI-01"));
    fireEvent.change(editor, { target: { value: editor.value.replace("poll_s: 30", "poll_s: 45") } });
    // Meanwhile the file is edited on disk → v9.
    simulateDiskEdit("controls.yaml", currentFiles()["controls.yaml"].replace("verify: sha256", "verify: sha256   # checked"));
    await user.type(screen.getByRole("textbox", { name: "Note for history" }), "Poll less often");
    await user.click(screen.getByRole("button", { name: "Save as v9" }));
    const conflict = await screen.findByRole("alert");
    expect(conflict).toHaveTextContent("controls.yaml changed while you were editing");
    expect(conflict).toHaveTextContent("Rogatka never overwrites a newer version.");
    expect(policyDb.versions).toHaveLength(9);
    await user.click(within(conflict).getByRole("button", { name: "Reload the file" }));
    await waitFor(() => expect((screen.getByRole("textbox", { name: "controls.yaml editor" }) as HTMLTextAreaElement).value).toContain("# checked"));
    expect((screen.getByRole("textbox", { name: "controls.yaml editor" }) as HTMLTextAreaElement).value).toContain("poll_s: 30");
    expect(screen.queryByText(/changed while you were editing/)).not.toBeInTheDocument();
  });

  it("is read-only for analysts, who can still validate", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?tab=yaml", user: ANALYST });
    const editor = await screen.findByRole("textbox", { name: "controls.yaml editor" });
    expect(editor).toHaveAttribute("readonly");
    expect(screen.getByRole("button", { name: "Validate" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.queryByRole("textbox", { name: "Note for history" })).not.toBeInTheDocument();
  });
});

describe("Policies: invalid file on disk", () => {
  it("shows a banner, keeps the last good version and opens the file", async () => {
    simulateDiskEdit("controls.yaml", "broken", { invalid: { line: 42, message: "bad indentation of a mapping entry" } });
    const { user } = renderApp(<PoliciesScreen />);
    const banner = await screen.findByText("controls.yaml on disk is invalid. Rogatka keeps v8, the last good version.");
    const box = banner.closest("[role=status]") as HTMLElement;
    expect(box).toHaveTextContent("controls.yaml L42 bad indentation of a mapping entry");
    expect(live()).toHaveTextContent("live v8");
    await user.click(within(box).getByRole("button", { name: "Open controls.yaml in YAML" }));
    expect(await screen.findByRole("textbox", { name: "controls.yaml editor" })).toBeInTheDocument();
  });

  it("shows no banner when the files are valid", async () => {
    renderApp(<PoliciesScreen />);
    await waitFor(() => expect(live()).toHaveTextContent("live v8"));
    expect(screen.queryByText(/on disk is invalid/)).not.toBeInTheDocument();
  });
});

describe("Policies: History", () => {
  it("lists versions with their source and shows the diff of the selected one", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?tab=history&sel=7" });
    const table = await screen.findByRole("table", { name: "Versions" });
    const v8 = (await within(table).findByText("v8")).closest("tr")!;
    expect(v8).toHaveTextContent("filesystem");
    expect(within(v8).getByText("file")).toBeInTheDocument();
    expect(v8).toHaveTextContent("live");
    expect(within(table).getByText("v5").closest("tr")).toHaveTextContent("rollback");
    expect(within(table).getByText("v5").closest("tr")).toHaveTextContent("Rolled back: the routing change sent too much to the local model");

    const side = await screen.findByRole("complementary", { name: "Version" });
    expect(side).toHaveTextContent("Injection threshold 0.75 → 0.80 to cut false alarms. Published from the panel by m.zielinska (controls.yaml).");
    const diff = await within(side).findByRole("list", { name: "Changes in controls.yaml" });
    const removed = within(diff).getAllByRole("listitem").filter((l) => l.dataset.kind === "del");
    const added = within(diff).getAllByRole("listitem").filter((l) => l.dataset.kind === "add");
    expect(removed.map((l) => l.textContent)).toEqual([expect.stringContaining("injection_threshold: 0.75")]);
    expect(added.map((l) => l.textContent)).toEqual([expect.stringContaining("injection_threshold: 0.80")]);
    expect(within(side).getByRole("link", { name: "First requests on v7 →" })).toHaveAttribute("href", "/traffic?q=v7");
  });

  it("shows the rollback reason of a version in its sidebar", async () => {
    renderApp(<PoliciesScreen />, { searchParams: "?tab=history&sel=5" });
    const side = await screen.findByRole("complementary", { name: "Version" });
    expect(side).toHaveTextContent("k.wojcik rolled the policy back from the panel because the routing change sent too much to the local model");
    expect(within(side).getByText("Reason")).toBeInTheDocument();
  });

  it("rolls back to a version after a confirmation with a reason", async () => {
    const { user } = renderApp(<PoliciesScreen />, { searchParams: "?tab=history&sel=6" });
    const side = await screen.findByRole("complementary", { name: "Version" });
    await user.click(await within(side).findByRole("button", { name: "Roll back to this version…" }));
    const dialog = await screen.findByRole("dialog", { name: "Roll back to v6?" });
    expect(dialog).toHaveTextContent("This creates a new version (v9) with the same files as v6.");
    await user.click(within(dialog).getByRole("button", { name: "Roll back to v6" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Write why you are rolling back.");
    await user.type(within(dialog).getByRole("textbox", { name: "Reason (required)" }), "ab");
    await user.click(within(dialog).getByRole("button", { name: "Roll back to v6" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Use at least 3 characters.");
    await user.clear(within(dialog).getByRole("textbox", { name: "Reason (required)" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Reason (required)" }), "Threshold change raised false alarms");
    await user.click(within(dialog).getByRole("button", { name: "Roll back to v6" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await within(side).findByText("v9 is live")).toBeInTheDocument();
    expect(side).toHaveTextContent("Rolled back to v6 · saved as policy v9.");
    await waitFor(() => expect(live()).toHaveTextContent("live v9 · rolled back just now by you"));
    const v9 = (await within(screen.getByRole("table", { name: "Versions" })).findByText("v9")).closest("tr")!;
    expect(v9).toHaveTextContent("rollback");
    expect(v9).toHaveTextContent("Rolled back: Threshold change raised false alarms");
    expect(policyDb.versions.at(-1)!.reason).toBe("Threshold change raised false alarms");
    expect(currentFiles()["controls.yaml"]).toContain("injection_threshold: 0.75");
  });

  it("the live version cannot be rolled back to, and viewers cannot roll back", async () => {
    const { unmount } = renderApp(<PoliciesScreen />, { searchParams: "?tab=history&sel=8" });
    const side = await screen.findByRole("complementary", { name: "Version" });
    expect(await within(side).findByText("This is the live version.")).toBeInTheDocument();
    unmount();
    renderApp(<PoliciesScreen />, { searchParams: "?tab=history&sel=6", user: VIEWER });
    const side2 = await screen.findByRole("complementary", { name: "Version" });
    expect(await within(side2).findByRole("button", { name: "Roll back to this version…" })).toBeDisabled();
  });
});

describe("Policies: errors", () => {
  it("shows an error with retry when the files cannot be loaded", async () => {
    server.use(http.get(adminPath("/policy/files/:name"), () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderApp(<PoliciesScreen />);
    expect(await screen.findByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

// Keep React in scope for the JSX in the vi.mock factory.
void React;
