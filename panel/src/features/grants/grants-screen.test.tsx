import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { renderApp } from "@/test/render";
import { DEV_USER } from "@/lib/auth/user";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { grants } from "@/mocks/db/grants";
import { GrantsScreen } from "./grants-screen";
import { ceilingCheck, expiresText, grantSentence, type GrantRowView } from "./model";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

async function table() {
  const t = await screen.findByRole("table", { name: "Grants" });
  await waitFor(() => expect(within(t).getAllByText("Jan Kowalski").length).toBeGreaterThan(0));
  return t;
}

const rowsOf = (t: HTMLElement) => within(t).getAllByRole("row").slice(1);

describe("Grants screen", () => {
  it("lists active grants with effect chips, limits and expiry; quick-filter counts", async () => {
    renderApp(<GrantsScreen />);
    expect(screen.getByRole("heading", { level: 1, name: "Grants" })).toBeInTheDocument();
    expect(screen.getByText("personal and temporary access on top of group rules")).toBeInTheDocument();
    const t = await table();
    await waitFor(() => expect(within(t).getByText("model smart → gemini")).toBeInTheDocument());
    const jan = within(t).getByText("model smart → gemini").closest("tr")!;
    expect(within(jan).getByText("Jan Kowalski")).toBeInTheDocument();
    expect(within(jan).getByText("≤ internal")).toBeInTheDocument();
    expect(within(jan).getByText("in 23 h")).toHaveClass("text-dec-downgrade");
    expect(within(t).getByText("1.00 USD / day")).toBeInTheDocument();
    expect(within(t).getAllByText("of developers 5.00")).toHaveLength(2);
    expect(within(t).queryByText("model smart-pro → gemini")).not.toBeInTheDocument(); // expired
    expect(screen.getByRole("button", { name: /Active 6/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /Expiring in 24 h 1/ })).toBeInTheDocument();
  });

  it("filters with the quick-filter pills and the search", async () => {
    const { user } = renderApp(<GrantsScreen />);
    const t = await table();
    await waitFor(() => expect(rowsOf(t)).toHaveLength(6));

    await user.click(screen.getByRole("button", { name: /Denials/ }));
    expect(rowsOf(t)).toHaveLength(1);
    expect(within(t).getByText("tool bash")).toBeInTheDocument();
    expect(within(t).getByText("deny")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Expiring in 24 h/ }));
    expect(rowsOf(t)).toHaveLength(1);
    expect(within(t).getByText("model smart → gemini")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /From approvals/ }));
    await waitFor(() => expect(within(t).getByText("approved request apr-0190")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /Temporary/ }));
    expect(rowsOf(t)).toHaveLength(3);

    await user.click(screen.getByRole("button", { name: /Active/ }));
    await user.type(screen.getByRole("searchbox", { name: "Search grants" }), "a.nowak");
    expect(rowsOf(t)).toHaveLength(2);
  });

  it("opens a grant: sentence, facts, LOCK-01 ceiling, history; Extend / Edit have no endpoint", async () => {
    renderApp(<GrantsScreen />, { searchParams: "?sel=g-0412" });
    const side = await screen.findByRole("complementary", { name: "Grant" });
    await waitFor(() => expect(within(side).getByText(/Jan Kowalski may use the cloud model smart \(Gemini\) for public and internal data until/)).toBeInTheDocument());
    expect(within(side).getByText(/Ceiling: LOCK-01 keeps confidential and restricted data away/)).toBeInTheDocument();
    await waitFor(() => expect(within(side).getByText("by m.zielinska · “Gemini pilot”")).toBeInTheDocument());
    expect(within(side).getByRole("button", { name: "Extend…" })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "Extend…" })).toHaveAttribute("title", "Not available in the admin API yet");
    expect(within(side).getByRole("button", { name: "Edit…" })).toBeDisabled();
    expect(within(side).getByRole("link", { name: "Open person →" })).toHaveAttribute("href", "/users?sel=j.kowalski");
  });

  it("revokes a grant with a required reason and shows the result inline", async () => {
    const { user } = renderApp(<GrantsScreen />, { searchParams: "?sel=g-0412" });
    const side = await screen.findByRole("complementary", { name: "Grant" });
    await user.click(await within(side).findByRole("button", { name: "Revoke" }));
    const form = within(side).getByRole("form", { name: "Revoke grant" });
    await user.click(within(form).getByRole("button", { name: "Revoke grant" }));
    expect(await within(form).findByText("A reason is required (at least 3 characters).")).toBeInTheDocument();
    await user.type(within(form).getByLabelText(/^Reason \(required\)/), "pilot ended early");
    await user.click(within(form).getByRole("button", { name: "Revoke grant" }));
    await waitFor(() => expect(within(side).getByText("Revoked")).toBeInTheDocument());
    expect(grants.items.find((g) => g.id === "g-0412")?.revoked_by).toBe("k.wojcik");
    // the sidebar stays open although the grant left the Active view; history shows the revoke
    await waitFor(() => expect(within(side).getByText("by k.wojcik · “pilot ended early”")).toBeInTheDocument());
    expect(within(side).getByRole("button", { name: "Grant again…" })).toBeInTheDocument();
  });

  it("removes a denial", async () => {
    const { user } = renderApp(<GrantsScreen />, { searchParams: "?sel=g-0415" });
    const side = await screen.findByRole("complementary", { name: "Grant" });
    await waitFor(() => expect(within(side).getByText(/Anna Nowak may not use the tool bash, although the group credit-analysts allows it/)).toBeInTheDocument());
    expect(within(side).queryByRole("button", { name: "Extend…" })).not.toBeInTheDocument();
    await user.click(within(side).getByRole("button", { name: "Remove denial" }));
    await user.type(within(side).getByLabelText(/^Reason \(required\)/), "needs shell for the migration");
    await user.click(within(within(side).getByRole("form", { name: "Remove denial" })).getByRole("button", { name: "Remove denial" }));
    expect(await within(side).findByText("Denial removed")).toBeInTheDocument();
  });

  it("creates a grant: ceiling check blocks confidential data for a cloud model, reason is required", async () => {
    const { user } = renderApp(<GrantsScreen />);
    await table();
    await user.click(screen.getByRole("button", { name: "+ New grant" }));
    const side = await screen.findByRole("complementary", { name: "New grant" });
    const form = within(side).getByRole("form", { name: "New grant" });
    await waitFor(() => expect(within(form).getByRole("option", { name: "Ewa Grabowska (e.grabowska)" })).toBeInTheDocument());
    await user.selectOptions(within(form).getByLabelText("Person or group"), "user:e.grabowska");
    expect(within(form).getByLabelText("What")).toHaveValue("alias:smart");
    expect(within(form).getByText("Within the limits. Cloud models can only get public and internal data (LOCK-01).")).toBeInTheDocument();

    await user.click(within(form).getByRole("checkbox", { name: "confidential" }));
    expect(within(form).getByRole("alert")).toHaveTextContent("Blocked by LOCK-01: cloud models never get confidential data");
    expect(within(form).getByRole("button", { name: "Create grant" })).toBeDisabled();
    await user.click(within(form).getByRole("checkbox", { name: "confidential" }));
    expect(within(form).getByRole("button", { name: "Create grant" })).toBeEnabled();

    await user.click(within(form).getByRole("button", { name: "Create grant" }));
    expect(await within(form).findByText("A reason is required (at least 3 characters).")).toBeInTheDocument();
    await user.click(within(form).getByRole("button", { name: "30 d" }));
    await user.type(within(form).getByLabelText(/^Reason \(required\)/), "Gemini pilot for reports");
    await user.click(within(form).getByRole("button", { name: "Create grant" }));

    const detail = await screen.findByRole("complementary", { name: "Grant" });
    expect(await within(detail).findByText("Grant g-0422 created")).toBeInTheDocument();
    expect(within(detail).getByText(/Ewa Grabowska may use the cloud model smart \(Gemini\) for public and internal data until/)).toBeInTheDocument();
    const created = grants.items.find((g) => g.id === "g-0422");
    expect(created).toMatchObject({ subject: "e.grabowska", resource: "smart", constraints: { data_classes: ["public", "internal"] } });
    expect(new Date(created!.expires_at!).getTime() - Date.now()).toBeGreaterThan(29 * 24 * 3600_000);
  });

  it("a deny grant needs no data classes and says it overrides the group", async () => {
    const { user } = renderApp(<GrantsScreen />, { searchParams: "?sel=new" });
    const form = await screen.findByRole("form", { name: "New grant" });
    await waitFor(() => expect(within(form).getByRole("option", { name: "group developers" })).toBeInTheDocument());
    await user.selectOptions(within(form).getByLabelText("Person or group"), "group:developers");
    await user.selectOptions(within(form).getByLabelText("What"), "tool:opencode.bash");
    await user.click(within(form).getByRole("button", { name: "Deny" }));
    expect(within(form).queryByText("Data classes")).not.toBeInTheDocument();
    expect(within(form).getByText(/A denial overrides what the group allows/)).toBeInTheDocument();
    await user.click(within(form).getByRole("button", { name: "never" }));
    await user.type(within(form).getByLabelText(/^Reason \(required\)/), "no shell this sprint");
    await user.click(within(form).getByRole("button", { name: "Create grant" }));
    expect(await screen.findByText("Grant g-0422 created")).toBeInTheDocument();
    expect(grants.items[0]).toMatchObject({ subject_type: "group", subject: "developers", effect: "deny", expires_at: null });
  });

  it("offers Grant again… on an ended grant, prefilled", async () => {
    const { user } = renderApp(<GrantsScreen />, { searchParams: "?view=ended&sel=g-0391" });
    const side = await screen.findByRole("complementary", { name: "Grant" });
    await waitFor(() => expect(within(side).getByText(/It has expired\./)).toBeInTheDocument());
    await user.click(within(side).getByRole("button", { name: "Grant again…" }));
    const form = await screen.findByRole("form", { name: "New grant" });
    expect(within(form).getByLabelText("Person or group")).toHaveValue("user:t.wisniewski");
    expect(within(form).getByLabelText("What")).toHaveValue("alias:smart-pro");
  });

  it("shows an error state when grants cannot load", async () => {
    server.use(http.get(adminPath("/grants"), () => HttpResponse.json({ detail: "database unavailable" }, { status: 503 })));
    renderApp(<GrantsScreen />);
    expect(await screen.findByText("database unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("is read-only for viewers", async () => {
    renderApp(<GrantsScreen />, { user: VIEWER, searchParams: "?sel=g-0412" });
    expect(screen.getByRole("button", { name: "+ New grant" })).toBeDisabled();
    const side = await screen.findByRole("complementary", { name: "Grant" });
    expect(await within(side).findByRole("button", { name: "Revoke" })).toBeDisabled();
  });
});

describe("grant model helpers", () => {
  it("checks the LOCK-01 ceiling", () => {
    expect(ceilingCheck({ effect: "allow", resourceType: "alias", resource: "smart", dataClasses: ["public", "restricted"] }).ok).toBe(false);
    expect(ceilingCheck({ effect: "allow", resourceType: "alias", resource: "local", dataClasses: ["confidential"] }).ok).toBe(true);
    expect(ceilingCheck({ effect: "deny", resourceType: "alias", resource: "smart", dataClasses: ["confidential"] }).ok).toBe(true);
  });

  it("formats expiry", () => {
    const now = Date.now();
    expect(expiresText(null, now)).toBe("never");
    expect(expiresText(new Date(now + 23 * 3600_000).toISOString(), now)).toBe("in 23 h");
    expect(expiresText(new Date(now + 9 * 60_000 + 40_000).toISOString(), now)).toBe("9:40 left");
    expect(expiresText(new Date(now + 6 * 86_400_000).toISOString(), now)).toBe("in 6 d");
  });

  it("writes the budget sentence", () => {
    const row = { source: "grant", effect: "budget", who: "Jan Kowalski", what: "1.00 USD / day", limits: "of developers 5.00", active: true, revoked: false, expiresAt: null, grant: {} } as unknown as GrantRowView;
    expect(grantSentence(row)).toBe("Jan Kowalski gets 1.00 USD a day from the developers budget of 5.00 USD.");
  });
});
