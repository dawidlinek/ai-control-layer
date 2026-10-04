import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { approvals } from "@/mocks/db/approvals";
import { grants } from "@/mocks/db/grants";
import { inMinutes } from "@/mocks/time";
import { UsersScreen } from "./users-screen";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };
const REASON = /^Reason \(required\)/;

async function person(name: string) {
  const side = await screen.findByRole("complementary", { name: "Person" });
  await within(side).findByText(name);
  const access = within(side).getByRole("list", { name: "Access" });
  await waitFor(() => expect(within(access).getAllByRole("listitem").length).toBeGreaterThan(3));
  return { side, access };
}

const accessRow = (access: HTMLElement, text: string | RegExp) => within(access).getByText(text).closest("li")!;

describe("Users & groups: People", () => {
  it("shows the tabs with derived counts and the people table", async () => {
    renderApp(<UsersScreen />);
    expect(screen.getByRole("heading", { level: 1, name: "Users & groups" })).toBeInTheDocument();
    expect(await screen.findByRole("tab", { name: "People 41" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("tab", { name: "Groups 4" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open Keycloak ↗" })).toBeDisabled();
    const table = screen.getByRole("table", { name: "People" });
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(26));
    const jan = within(table).getByText("Jan Kowalski").closest("tr")!;
    expect(within(jan).getByText("jan.kowalski@corp.example")).toBeInTheDocument();
    expect(within(jan).getByText("developers")).toBeInTheDocument();
    expect(within(jan).getByText("1.2M / 310k")).toBeInTheDocument();
    expect(within(jan).getByText("3")).toHaveClass("text-dec-block");
    expect(screen.getByRole("button", { name: "2" })).toBeInTheDocument();
  });

  it("searches and filters by group", async () => {
    const { user } = renderApp(<UsersScreen />);
    const table = await screen.findByRole("table", { name: "People" });
    await waitFor(() => expect(within(table).getByText("Jan Kowalski")).toBeInTheDocument());
    await user.type(screen.getByRole("searchbox", { name: "Search people or groups" }), "anna.nowak");
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(2));
    await user.clear(screen.getByRole("searchbox", { name: "Search people or groups" }));
    await user.click(screen.getByRole("button", { name: /^Group/ }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "operations" }));
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(13));
  });

  it("grants a cloud model inline: validation, StatusBox result, 'smart (new)'", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?sel=p.zielinski" });
    const { side, access } = await person("Piotr Zieliński");
    expect(within(side).getByText(/piotr\.zielinski@corp\.example · developers · balanced/)).toBeInTheDocument();
    expect(within(side).getByText(/1 530 requests · 1.8M \/ 420k tokens in \/ out/)).toBeInTheDocument();
    expect(within(accessRow(access, "smart → gemini")).getByText("not in group developers")).toBeInTheDocument();

    await user.click(within(access).getByRole("button", { name: "Grant smart → gemini" }));
    const form = within(side).getByRole("form", { name: "Grant access" });
    expect(within(form).getByText(/Give Piotr access to/)).toBeInTheDocument();
    expect(within(form).getByText("× confidential · LOCK-01")).toBeInTheDocument();
    expect(within(form).getByRole("checkbox", { name: "public" })).toBeChecked();
    expect(within(form).getByRole("button", { name: "7 d" })).toHaveAttribute("aria-pressed", "true");

    await user.click(within(form).getByRole("button", { name: "Grant access" }));
    expect(await within(form).findByText("A reason is required (at least 3 characters).")).toBeInTheDocument();
    await user.type(within(form).getByLabelText(REASON), "Gemini pilot");
    await user.click(within(form).getByRole("button", { name: "Grant access" }));

    expect(await within(side).findByText(/^Piotr can use smart → gemini until/)).toBeInTheDocument();
    expect(within(side).getByText(/Saved as grant g-0422/)).toBeInTheDocument();
    const seen = within(side).getByRole("list", { name: "Their clients see" });
    await waitFor(() => expect(within(seen).getByText(/smart\s*\(new\)/)).toBeInTheDocument());
    await waitFor(() => expect(within(access).getByText("grant g-0422 · “Gemini pilot” · ≤ internal")).toBeInTheDocument());
    expect(within(access).getByText("grant g-0422 · “Gemini pilot” · ≤ internal").closest("li")).toHaveClass("bg-accent-soft");
  });

  it("revokes Jan's personal grant g-0412", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?sel=j.kowalski" });
    const { side, access } = await person("Jan Kowalski");
    await waitFor(() => expect(within(access).getByText("grant g-0412 · “Gemini pilot” · ≤ internal")).toBeInTheDocument());
    expect(within(access).getByText("1.00 USD / day")).toBeInTheDocument();
    expect(within(side).getByRole("list", { name: "Their clients see" })).toHaveTextContent("smart");

    await user.click(within(access).getByRole("button", { name: "Revoke smart → gemini" }));
    await user.type(within(side).getByLabelText(REASON), "pilot over");
    await user.click(within(side).getByRole("button", { name: "Revoke grant" }));
    expect(await within(side).findByText("Revoked g-0412")).toBeInTheDocument();
    await waitFor(() => expect(within(accessRow(access, "smart → gemini")).getByText("not in group developers")).toBeInTheDocument());
    expect(grants.items.find((g) => g.id === "g-0412")?.revoked_at).not.toBeNull();
  });

  it("takes a group tool away from one person (user deny) and restores Anna's bash", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?sel=j.kowalski" });
    const { side, access } = await person("Jan Kowalski");
    await user.click(within(access).getByRole("button", { name: "Revoke bash" }));
    await user.type(within(side).getByLabelText(REASON), "no shell on this project");
    await user.click(within(side).getByRole("button", { name: "Deny bash" }));
    expect(await within(side).findByText("bash denied for Jan")).toBeInTheDocument();
    await waitFor(() => expect(within(access).getByText("user deny g-0422 · overrides group")).toBeInTheDocument());
    expect(within(access).getByRole("button", { name: "Restore bash" })).toBeInTheDocument();
  });

  it("restores a denied tool", async () => {
    const { user } = renderApp(<UsersScreen />, { searchParams: "?sel=a.nowak" });
    const { side, access } = await person("Anna Nowak");
    expect(within(accessRow(access, "user deny g-0415 · overrides group")).getByRole("img", { name: "denied" })).toBeInTheDocument();
    expect(within(access).getByText("jira")).toBeInTheDocument();
    await user.click(within(access).getByRole("button", { name: "Restore bash" }));
    await user.type(within(side).getByLabelText(REASON), "needs shell again");
    await user.click(within(side).getByRole("button", { name: "Restore" }));
    expect(await within(side).findByText("bash restored for Anna")).toBeInTheDocument();
    await waitFor(() => expect(within(access).queryByText("user deny g-0415 · overrides group")).not.toBeInTheDocument());
    expect(within(access).getByRole("button", { name: "Revoke bash" })).toBeInTheDocument();
  });

  it("shows an approved elevation, recent activity and the cross-screen links", async () => {
    const apr = approvals.items.find((a) => a.id === "apr-0193")!;
    Object.assign(apr, { status: "approved", decided_by: "k.wojcik", decided_at: new Date().toISOString(), elevation: { scope: "tool:opencode.bash", until: inMinutes(15) } });
    renderApp(<UsersScreen />, { searchParams: "?sel=j.kowalski" });
    const { side, access } = await person("Jan Kowalski");
    await waitFor(() => expect(within(access).getByText("approved apr-0193 by k.wojcik")).toBeInTheDocument());
    const activity = within(side).getByRole("list", { name: "Recent activity" });
    await waitFor(() => expect(within(activity).getAllByRole("link").length).toBeGreaterThan(0));
    expect(within(activity).getAllByText("bash").length).toBeGreaterThan(0);
    expect(within(side).getByRole("link", { name: "All activity in Traffic →" })).toHaveAttribute("href", "/traffic?q=j.kowalski");
    expect(within(side).getByRole("link", { name: "Grant history →" })).toHaveAttribute("href", "/grants?q=j.kowalski");
  });

  it("shows an error when access cannot load", async () => {
    server.use(http.get(adminPath("/users/:id/effective-access"), () => HttpResponse.json({ detail: "resolver offline" }, { status: 503 })));
    renderApp(<UsersScreen />, { searchParams: "?sel=j.kowalski" });
    expect(await screen.findByText("resolver offline")).toBeInTheDocument();
  });

  it("is read-only for viewers", async () => {
    renderApp(<UsersScreen />, { user: VIEWER, searchParams: "?sel=j.kowalski" });
    const { side, access } = await person("Jan Kowalski");
    expect(within(side).getByRole("button", { name: "+ Grant" })).toBeDisabled();
    expect(within(access).queryByRole("button")).not.toBeInTheDocument();
  });
});
