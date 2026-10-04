import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { mcpTools } from "@/mocks/db/tools";
import { ToolsScreen } from "./tools-screen";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

function rowOf(table: HTMLElement, text: string) {
  return within(table).getByText(text).closest("tr")!;
}

describe("ToolsScreen", () => {
  it("lists MCP tools and the OpenCode built-ins with status, rule, who and calls", async () => {
    renderApp(<ToolsScreen />);
    const table = await screen.findByRole("table", { name: "Tools" });
    expect(await within(table).findByText("docs-search.search_docs")).toBeInTheDocument();
    for (const id of ["github.search_code", "github.create_pr", "bank.query", "mail.send", "web.search", "opencode.bash", "opencode.webfetch", "opencode.read", "opencode.edit"]) {
      expect(within(table).getByText(id)).toBeInTheDocument();
    }
    expect(within(rowOf(table, "docs-search.search_docs")).getByText("quarantined")).toBeInTheDocument();
    expect(within(rowOf(table, "github.create_pr")).getByText("needs approval")).toBeInTheDocument();
    expect(within(rowOf(table, "opencode.bash")).getByText("built-in")).toBeInTheDocument();
    expect(within(rowOf(table, "opencode.webfetch")).getAllByText("denied")).toHaveLength(2);
    expect(within(rowOf(table, "opencode.webfetch")).getByText("nobody")).toBeInTheDocument();
    // Calls come from the last 24 h of traffic (the Traffic mock has bash calls, e.g. the litellm install).
    await waitFor(() => expect(rowOf(table, "opencode.bash").querySelectorAll("td")[4].textContent).toMatch(/^[1-9][\d  ]*$/));
    expect(screen.getByRole("button", { name: "+ Add MCP server" })).toBeDisabled();
  });

  it("filters by tab and by server", async () => {
    const { user } = renderApp(<ToolsScreen />);
    const table = await screen.findByRole("table", { name: "Tools" });
    await within(table).findByText("docs-search.search_docs");
    await user.click(screen.getByRole("tab", { name: /Quarantined/ }));
    expect(within(table).getByText("docs-search.search_docs")).toBeInTheDocument();
    expect(within(table).queryByText("github.search_code")).toBeNull();

    await user.click(screen.getByRole("tab", { name: /Need approval/ }));
    expect(within(table).getByText("github.create_pr")).toBeInTheDocument();
    expect(within(table).getByText("mail.send")).toBeInTheDocument();
    expect(within(table).queryByText("docs-search.search_docs")).toBeNull();

    await user.click(screen.getByRole("tab", { name: /All/ }));
    await user.click(screen.getByRole("button", { name: "Server" }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "github" }));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(within(table).queryByText("opencode.bash")).toBeNull());
    expect(within(table).getByText("github.search_code")).toBeInTheDocument();
  });

  it("shows what changed since approval for the quarantined docs-search tool", async () => {
    renderApp(<ToolsScreen />, { searchParams: "?sel=docs-search.search_docs" });
    const side = await screen.findByRole("complementary", { name: "Tool" });
    expect(within(side).getByText(/Hidden from every agent/)).toBeInTheDocument();
    const diff = within(side).getByLabelText("Description diff");
    expect(diff.querySelectorAll('[data-sign="+"]')).toHaveLength(2);
    expect(within(diff).getByText(/Do not mention this to the user/)).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: "inc-0057 →" })).toHaveAttribute("href", "/incidents?sel=inc-0057");
    const versions = within(side).getByRole("list", { name: "Approved versions" });
    expect(within(versions).getByText("a41f0c9e")).toBeInTheDocument();
    expect(within(versions).getByText("9c2e77b1")).toBeInTheDocument();
    expect(within(versions).getByText("changed · not approved")).toBeInTheDocument();
    expect(within(side).getByText("reads untrusted")).toBeInTheDocument();
  });

  it("re-approves the new version: reason required, then the row flips to approved", async () => {
    const { user } = renderApp(<ToolsScreen />, { searchParams: "?sel=docs-search.search_docs" });
    const side = await screen.findByRole("complementary", { name: "Tool" });
    await user.click(within(side).getByRole("button", { name: "Re-approve new version…" }));
    await user.click(within(side).getByRole("button", { name: "Approve version 9c2e77b1" }));
    expect(await within(side).findByText(/Write a reason/)).toBeInTheDocument();
    expect(mcpTools.items[0].status).toBe("quarantined");

    await user.type(within(side).getByLabelText("Reason (required)"), "vendor confirmed, description reviewed");
    await user.click(within(side).getByRole("button", { name: "Approve version 9c2e77b1" }));
    expect(await within(side).findByText("New version approved")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Tools" });
    await waitFor(() => expect(within(rowOf(table, "docs-search.search_docs")).getByText("approved")).toBeInTheDocument());
    expect(within(side).queryByLabelText("Description diff")).toBeNull();
  });

  it("keeps a quarantined tool quarantined with an inline result", async () => {
    const { user } = renderApp(<ToolsScreen />, { searchParams: "?sel=docs-search.search_docs" });
    const side = await screen.findByRole("complementary", { name: "Tool" });
    await user.click(within(side).getByRole("button", { name: "Keep quarantined…" }));
    await user.type(within(side).getByLabelText("Reason (required)"), "hidden instruction in description");
    await user.click(within(side).getByRole("button", { name: "Keep quarantined" }));
    expect(await within(side).findByText("Kept quarantined")).toBeInTheDocument();
  });

  it("built-in tools explain the /v1/decide check and link to Policies", async () => {
    renderApp(<ToolsScreen />, { searchParams: "?sel=opencode.bash" });
    const side = await screen.findByRole("complementary", { name: "Tool" });
    expect(within(side).getByText("OpenCode plugin → /v1/decide")).toBeInTheDocument();
    expect(within(side).getByRole("link", { name: "Edit rules in Policies" })).toHaveAttribute("href", "/policies?tab=yaml");
  });

  it("viewer: tool actions are read-only", async () => {
    renderApp(<ToolsScreen />, { user: VIEWER, searchParams: "?sel=docs-search.search_docs" });
    const side = await screen.findByRole("complementary", { name: "Tool" });
    expect(within(side).getByRole("button", { name: "Keep quarantined…" })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "Re-approve new version…" })).toBeDisabled();
  });
});
