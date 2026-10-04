import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { groups } from "@/mocks/db/users";
import { policyStatus } from "@/mocks/db/policy";
import { UsersScreen } from "./users-screen";
import { prettyChange } from "./groups";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

async function groupSidebar() {
  const side = await screen.findByRole("complementary", { name: "Group" });
  await waitFor(() => expect(within(side).getByRole("switch", { name: /smart \(gemini\)/ })).toBeInTheDocument());
  return side;
}

describe("Users & groups: Groups", () => {
  it("lists groups with members, preset, models, tokens and spend today", async () => {
    renderApp(<UsersScreen />, { searchParams: "?tab=groups" });
    const table = await screen.findByRole("table", { name: "Groups" });
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(5));
    const dev = within(table).getByText("developers").closest("tr")!;
    expect(within(dev).getByText("14")).toBeInTheDocument();
    expect(within(dev).getByText("balanced")).toBeInTheDocument();
    expect(within(dev).getByText("auto · fast · local")).toBeInTheDocument();
    expect(within(dev).getByText("2.4M / 610k")).toBeInTheDocument();
    expect(within(dev).getByText("2.10 USD")).toBeInTheDocument();
  });

  it("toggles models and tools, previews the change, saves it as policy v9", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?tab=groups&sel=developers" });
    const side = await groupSidebar();
    expect(within(side).getByText(/^Keycloak group/)).toHaveTextContent("Keycloak group · 14 members · 2.4M / 610k tokens today");
    expect(within(side).getByRole("button", { name: "balanced" })).toHaveAttribute("aria-pressed", "true");
    expect(within(side).getByRole("switch", { name: /smart \(gemini\)/ })).toHaveAttribute("aria-checked", "false");

    await user.click(within(side).getByRole("switch", { name: /smart \(gemini\)/ }));
    await user.click(within(side).getByRole("switch", { name: /bash/ }));
    await user.click(within(side).getByRole("button", { name: "Raise budget" }));
    expect(within(side).getByText("6.00 USD")).toBeInTheDocument();

    const bar = within(side).getByRole("region", { name: "Unsaved changes" });
    await waitFor(() =>
      expect(bar).toHaveTextContent("3 changes: + smart (gemini), − bash, budget 5 → 6 USD · written to groups.yaml, budgets.yaml"),
    );
    const save = within(bar).getByRole("button", { name: "Save as policy v9" });
    await waitFor(() => expect(save).toBeEnabled());
    await user.click(save);

    expect(await within(side).findByText("v9 is live.")).toBeInTheDocument();
    expect(within(side).queryByRole("region", { name: "Unsaved changes" })).not.toBeInTheDocument();
    expect(policyStatus.version).toBe("v9");
    expect(groups.items.find((g) => g.name === "developers")?.settings).toMatchObject({ daily_budget_usd: 6, models: ["auto", "fast", "local", "smart"] });
    expect(groups.items.find((g) => g.name === "developers")?.settings?.tools).not.toContain("opencode.bash");
    const table = screen.getByRole("table", { name: "Groups" });
    await waitFor(() => expect(within(table).getByText("auto · fast · local · smart")).toBeInTheDocument());
  });

  it("discards unsaved changes", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?tab=groups&sel=developers" });
    const side = await groupSidebar();
    await user.click(within(side).getByRole("button", { name: "strict" }));
    const bar = within(side).getByRole("region", { name: "Unsaved changes" });
    await waitFor(() => expect(bar).toHaveTextContent("1 change: preset balanced → strict · written to groups.yaml"));
    await user.click(within(bar).getByRole("button", { name: "Discard" }));
    expect(within(side).queryByRole("region", { name: "Unsaved changes" })).not.toBeInTheDocument();
    expect(within(side).getByRole("button", { name: "balanced" })).toHaveAttribute("aria-pressed", "true");
    expect(policyStatus.version).toBe("v8");
  });

  it("reports an invalid combination from the preview and blocks saving", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?tab=groups&sel=developers" });
    const side = await groupSidebar();
    await user.click(within(side).getByRole("switch", { name: /smart \(gemini\)/ }));
    await user.click(within(side).getByRole("button", { name: "nothing" }));
    expect(await within(side).findByText("This change is not valid")).toBeInTheDocument();
    expect(within(side).getByText(/remove cloud models first/)).toBeInTheDocument();
    expect(within(side).getByRole("button", { name: /Save as policy/ })).toBeDisabled();
    expect(within(side).getByText("confidential and above: never (LOCK-01)")).toBeInTheDocument();
  });

  it("lists members with personal-grant notes and the Keycloak placeholder", async () => {
    renderApp(<UsersScreen />, { searchParams: "?tab=groups&sel=developers" });
    const side = await groupSidebar();
    const members = within(side).getByRole("list", { name: "Members" });
    await waitFor(() => expect(within(members).getByText("personal grant: smart")).toBeInTheDocument());
    expect(within(members).getByText("Jan Kowalski")).toBeInTheDocument();
    expect(within(members).getByText("11 more")).toBeInTheDocument();
    expect(within(side).getByRole("button", { name: "Manage in Keycloak ↗" })).toBeDisabled();
  });

  it("is read-only for viewers", async () => {
    renderApp(<UsersScreen />, { user: VIEWER, searchParams: "?tab=groups&sel=developers" });
    const side = await groupSidebar();
    expect(within(side).getByText(/Only admins can change it\./)).toBeInTheDocument();
    expect(within(side).getByRole("switch", { name: /smart \(gemini\)/ })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "strict" })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "Raise budget" })).toBeDisabled();
  });

  it("switching tabs clears the selection", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?tab=groups&sel=developers" });
    await groupSidebar();
    await user.click(screen.getByRole("tab", { name: /People/ }));
    expect(await screen.findByRole("table", { name: "People" })).toBeInTheDocument();
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
  });
});

describe("prettyChange", () => {
  it("shortens the gateway's change strings", () => {
    expect(prettyChange("+ model smart")).toBe("+ smart (gemini)");
    expect(prettyChange("- tool opencode.bash")).toBe("− bash");
    expect(prettyChange("daily budget 5 → 6 USD")).toBe("budget 5 → 6 USD");
    expect(prettyChange("cloud data internal → public")).toBe("cloud data internal → public");
  });
});
