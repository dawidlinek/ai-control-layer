import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { renderApp } from "@/test/render";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { approvals } from "@/mocks/db/approvals";
import { useNavCounts } from "@/lib/api/hooks";
import { DEV_USER } from "@/lib/auth/user";
import { ApprovalsScreen } from "./approvals-screen";
import { parseArguments, parseReason } from "./readers";

function PendingBadge() {
  const { approvals: n } = useNavCounts();
  return <span data-testid="badge">{n ?? "…"}</span>;
}

const table = () => screen.findByRole("table", { name: "Approval requests" });
const sidebar = () => screen.getByRole("complementary", { name: "Approval request" });

describe("ApprovalsScreen", () => {
  it("lists waiting requests with tab counts, approver and the auto-deny note", async () => {
    renderApp(<ApprovalsScreen />);
    const t = await table();
    await waitFor(() => expect(within(t).getAllByRole("row")).toHaveLength(4)); // header + 3
    expect(screen.getByRole("tab", { name: /Waiting\s*3/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /Decided · 24 h\s*3/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /All\s*6/ })).toBeInTheDocument();
    expect(screen.getByText("Requests nobody answers are denied after 10 minutes")).toBeInTheDocument();
    const jan = within(t).getByText("apr-0193").closest("tr")!;
    expect(within(jan).getByText("git push")).toBeInTheDocument();
    expect(within(jan).getByText("Rule of Two")).toBeInTheDocument();
    expect(within(jan).getByText("Security team")).toBeInTheDocument();
    expect(jan.querySelector("[data-urgent]")).not.toBeNull();
    const bot = within(t).getByText("apr-0194").closest("tr")!;
    expect(within(bot).getByText("Team lead")).toBeInTheDocument();
    expect(within(bot).getByText("agent for Anna Nowak")).toBeInTheDocument();
    expect(bot.querySelector("[data-urgent]")).toBeNull();
  });

  it("switches tabs and filters by approver", async () => {
    const { user } = renderApp(<ApprovalsScreen />);
    const t = await table();
    await waitFor(() => expect(within(t).getAllByRole("row")).toHaveLength(4));
    await user.click(screen.getByRole("tab", { name: /Decided/ }));
    await waitFor(() => expect(within(t).getByText("apr-0188")).toBeInTheDocument());
    expect(within(t).queryByText("apr-0193")).toBeNull();
    expect(within(t).getByText("denied")).toBeInTheDocument();
    expect(within(t).getByText("expired")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /All/ }));
    await user.click(screen.getByRole("button", { name: /Approver/ }));
    await user.click(await screen.findByRole("menuitemcheckbox", { name: "Team lead" }));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(within(t).queryByText("apr-0193")).toBeNull());
    expect(within(t).getByText("apr-0194")).toBeInTheDocument();
  });

  it("shows what it wants to do, red flags, the masked preview and the Rule-of-Two reasons", async () => {
    renderApp(<ApprovalsScreen />, { searchParams: "?sel=apr-0193" });
    await table();
    const s = await waitFor(sidebar);
    expect(within(s).getByText(/auto-deny in/)).toBeInTheDocument();
    expect(within(s).getByTestId("approval-command")).toHaveTextContent("git push origin feature/loan-calc");
    expect(within(s).getByText("not a company remote")).toBeInTheDocument();
    expect(within(s).getByText("secret found")).toBeInTheDocument();
    expect(within(s).getByText('SCORING_API_KEY = "‹SECRET:api_key›"')).toBeInTheDocument();
    expect(within(s).getByText(/Jan Kowalski’s agent wants to run git push to github.com\/jk-priv\/loan-calc/)).toBeInTheDocument();
    expect(within(s).getByText("confidential")).toBeInTheDocument();
    expect(within(s).getByRole("link", { name: "tr_9b21e4" })).toHaveAttribute("href", "/traffic?sel=tr_9b21e4");
    expect(within(s).getByRole("link", { name: "SEC-FLOW-01" })).toBeInTheDocument();
    const reasons = within(within(s).getByRole("list", { name: "Reasons" })).getAllByRole("listitem");
    expect(reasons.map((li) => li.textContent)).toEqual([
      expect.stringContaining("untrusted"),
      expect.stringContaining("sensitive"),
      expect.stringContaining("external"),
    ]);
    expect(within(reasons[0]).getByRole("link")).toHaveAttribute("href", "/traffic?sel=tr_9a8810");
    expect(within(s).getByRole("link", { name: "Open full session s_9e21 →" })).toHaveAttribute("href", "/sessions/s_9e21");
  });

  it("requires a reason to approve, then approves once: status box, row flips, badge updates", async () => {
    const { user } = renderApp(
      <>
        <PendingBadge />
        <ApprovalsScreen />
      </>,
      { searchParams: "?sel=apr-0193" },
    );
    await table();
    await waitFor(() => expect(screen.getByTestId("badge")).toHaveTextContent("3"));
    const s = await waitFor(sidebar);
    await user.click(within(s).getByRole("button", { name: "Approve once" }));
    expect(await within(s).findByText("Write a reason to approve.")).toBeInTheDocument();
    expect(approvals.items.find((a) => a.id === "apr-0193")!.status).toBe("pending");

    await user.type(within(s).getByLabelText("Reason (required to approve)"), "pushes to a private remote");
    await user.click(within(s).getByRole("button", { name: "Approve once" }));
    const box = await within(sidebar()).findByRole("status");
    expect(box).toHaveTextContent("Approved once");
    expect(box).toHaveTextContent("git push to github.com/jk-priv/loan-calc runs now.");
    expect(approvals.items.find((a) => a.id === "apr-0193")!.status).toBe("approved");
    expect(approvals.items.find((a) => a.id === "apr-0193")!.elevation).toBeNull();

    const row = within(await table()).getByText("apr-0193").closest("tr")!;
    await waitFor(() => expect(within(row).getByText("approved")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("badge")).toHaveTextContent("2"));
    expect(screen.getByRole("tab", { name: /Waiting\s*2/ })).toBeInTheDocument();
  });

  it("denies without a reason (Deny is the primary red button)", async () => {
    const { user } = renderApp(<ApprovalsScreen />, { searchParams: "?sel=apr-0193" });
    await table();
    const s = await waitFor(sidebar);
    const deny = within(s).getByRole("button", { name: "Deny" });
    expect(deny.className).toContain("bg-dec-block");
    await user.click(deny);
    expect(await within(sidebar()).findByText("Denied")).toBeInTheDocument();
    expect(sidebar()).toHaveTextContent("The client shows the denial with rule SEC-FLOW-01 and trace tr_9b21e4.");
    expect(approvals.items.find((a) => a.id === "apr-0193")!.status).toBe("denied");
    const row = within(await table()).getByText("apr-0193").closest("tr")!;
    await waitFor(() => expect(within(row).getByText("denied")).toBeInTheDocument());
  });

  it("approves for 60 minutes and explains the elevation", async () => {
    const { user } = renderApp(<ApprovalsScreen />, { searchParams: "?sel=apr-0193" });
    await table();
    const s = await waitFor(sidebar);
    await user.type(within(s).getByLabelText("Reason (required to approve)"), "checked with Jan");
    await user.click(within(s).getByRole("button", { name: "60m" }));
    expect(within(s).getByRole("button", { name: "60m" })).toHaveAttribute("aria-pressed", "true");
    await user.click(within(s).getByRole("button", { name: "Approve for 60 minutes" }));
    const box = await within(sidebar()).findByRole("status");
    expect(box).toHaveTextContent("Approved for 60 minutes");
    expect(box).toHaveTextContent("It shows as an elevation on Jan Kowalski’s access page.");
    const a = approvals.items.find((x) => x.id === "apr-0193")!;
    expect(a.status).toBe("approved");
    const mins = (Date.parse(a.elevation!.until) - Date.now()) / 60_000;
    expect(mins).toBeGreaterThan(58);
    expect(mins).toBeLessThanOrEqual(60);
  });

  it("shows the error inline and keeps the reason when deciding fails", async () => {
    server.use(http.post(adminPath("/approvals/:id/decision"), () => HttpResponse.json({ detail: "approval already denied" }, { status: 409 })));
    const { user } = renderApp(<ApprovalsScreen />, { searchParams: "?sel=apr-0193" });
    await table();
    const s = await waitFor(sidebar);
    await user.type(within(s).getByLabelText("Reason (required to approve)"), "ok");
    await user.click(within(s).getByRole("button", { name: "Approve once" }));
    const alert = await within(s).findByRole("alert");
    expect(alert).toHaveTextContent("Could not approve");
    expect(alert).toHaveTextContent("approval already denied");
    expect(within(s).getByLabelText("Reason (required to approve)")).toHaveValue("ok");
  });

  it("counts down live", async () => {
    renderApp(<ApprovalsScreen />, { searchParams: "?sel=apr-0193" });
    await table();
    const pill = within(await waitFor(sidebar)).getByText(/auto-deny in/);
    const first = pill.textContent;
    expect(first).toMatch(/auto-deny in 9:[34]\d/);
    await waitFor(() => expect(pill.textContent).not.toBe(first), { timeout: 2500 });
  });

  it("is read-only for viewers", async () => {
    renderApp(<ApprovalsScreen />, {
      searchParams: "?sel=apr-0193",
      user: { ...DEV_USER, role: "viewer", roles: ["acl-viewer"] },
    });
    await table();
    const s = await waitFor(sidebar);
    expect(within(s).queryByRole("button", { name: "Deny" })).toBeNull();
    expect(within(s).queryByRole("button", { name: "Approve once" })).toBeNull();
    expect(within(s).getByText(/needs the analyst or admin role/)).toBeInTheDocument();
  });

  it("shows an error state with retry when the list fails", async () => {
    server.use(http.get(adminPath("/approvals"), () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderApp(<ApprovalsScreen />);
    expect(await screen.findByText("Could not load this")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

describe("approval readers", () => {
  it("tolerates a one-line preview and reason", () => {
    const p = parseArguments({ arguments_preview: "rm -rf build", tool: "bash" });
    expect(p).toMatchObject({ command: "rm -rf build", details: [], preview: null, dataClass: null });
    expect(parseReason({ reason: "irreversible command" })).toEqual({ short: "irreversible command", sources: [] });
  });

  it("flags company vs external targets deterministically", () => {
    const p = parseArguments({
      arguments_preview: "x\nRemote: git.corp.example/dev/a\nTo: a@corp.example, b@partner.pl\nSecret scan: none",
      tool: "bash",
    });
    expect(p.details.map((d) => d.flag)).toEqual([undefined, "outside @corp.example", undefined]);
  });
});
