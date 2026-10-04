import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/server";
import { adminPath, problem } from "@/mocks/handlers/helpers";
import { budgetNodes } from "@/mocks/db/budgets";
import { DEV_USER } from "@/lib/auth/user";
import { renderApp } from "@/test/render";
import { BudgetsScreen } from "./budgets-screen";
import { flattenTree, isIdleSession, shortSessionId } from "./model";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

function renderBudgets(search?: string, opts: Parameters<typeof renderApp>[1] = {}) {
  return renderApp(<BudgetsScreen />, { searchParams: search, urlMemory: true, ...opts });
}

const rowOf = async (name: RegExp | string) => {
  const table = await screen.findByRole("table", { name: "Budget tree" });
  const cell = await within(table).findByText(name);
  return cell.closest("tr")!;
};

describe("BudgetsScreen", () => {
  it("selects the research-bot session with the open breaker by default", async () => {
    renderBudgets();
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    expect(within(sidebar).getByText("session s_77c1")).toBeInTheDocument();
    expect(within(sidebar).getByText("Breaker open.")).toBeInTheDocument();
    expect(within(sidebar).getByText(/same search ran 3 times in 60 s/)).toBeInTheDocument();
    expect(within(sidebar).getByText(/It tries again in/)).toBeInTheDocument();
    expect(within(sidebar).getByText("120 GPU-s")).toBeInTheDocument();
    expect(within(sidebar).getByRole("img", { name: "Spend per hour today" })).toBeInTheDocument();
    const byModel = within(sidebar).getByRole("list", { name: "By model" });
    expect(within(byModel).getByText("local/qwen3.8-27b")).toBeInTheDocument();
    expect(within(byModel).getByText("82 GPU-s")).toBeInTheDocument();
    expect(within(sidebar).getByRole("link", { name: "budgets.yaml L15" })).toHaveAttribute(
      "href",
      "/policies?tab=yaml&file=budgets.yaml&line=15",
    );
    expect(within(sidebar).getByRole("link", { name: "Requests in Traffic →" })).toHaveAttribute("href", "/traffic?q=s_77c1");
    expect((await rowOf("session s_77c1")).getAttribute("aria-selected")).toBe("true");
  });

  it("renders the tree company → groups → people / agent → session with breakers", async () => {
    renderBudgets();
    const table = await screen.findByRole("table", { name: "Budget tree" });
    await rowOf("Jan Kowalski");
    const names = within(table)
      .getAllByRole("row")
      .slice(1)
      .map((r) => r.querySelector("td")?.textContent);
    expect(names).toEqual([
      "Whole companyorg",
      "developersgroup",
      "Jan Kowalskiperson",
      "Piotr Zielińskiperson",
      "credit-analystsgroup",
      "Anna Nowakperson",
      "research-botagent",
      "session s_77c1agent session",
      "operationsgroup",
      "securitygroup",
    ]);
    const org = await rowOf("Whole company");
    expect(within(org).getByText("3.12 USD")).toBeInTheDocument();
    expect(within(org).getByText("of 5.00")).toBeInTheDocument();
    expect(within(org).getByText("4.40")).toBeInTheDocument();
    expect(within(org).getByText("closed")).toBeInTheDocument();
    const piotr = await rowOf("Piotr Zieliński");
    expect(within(piotr).getByText("alert at 80%")).toBeInTheDocument();
    expect(within(piotr).getByRole("meter")).toHaveAttribute("data-state", "warning");
    const session = await rowOf("session s_77c1");
    expect(within(session).getByText(/^open · \d:\d\d$/)).toBeInTheDocument();
    expect(within(session).getByRole("meter")).toHaveAttribute("data-state", "danger");
    expect(within(await rowOf("Anna Nowak")).getByText("group share")).toBeInTheDocument();
    expect(within(await rowOf("research-bot")).getByText("no own limit")).toBeInTheDocument();
  });

  it("shows the three summary cards and switches to this month", async () => {
    const { user } = renderBudgets();
    const spent = await screen.findByRole("region", { name: "Spent today" });
    expect(within(spent).getByText("3.12")).toBeInTheDocument();
    expect(within(spent).getByText("of 5.00 USD")).toBeInTheDocument();
    expect(within(spent).getByText("forecast 4.40 by midnight")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Local GPU time" })).getByText("1 912")).toBeInTheDocument();
    expect(screen.getByText("guards use 350 GPU-s of it")).toBeInTheDocument();
    const saved = screen.getByRole("region", { name: "Saved vs sending everything to the cloud" });
    expect(within(saved).getByText("61%")).toBeInTheDocument();
    expect(within(saved).getByText("≈ 4.90 USD today")).toBeInTheDocument();

    await user.click(within(screen.getByRole("group", { name: "Period" })).getByRole("button", { name: "This month" }));
    const month = await screen.findByRole("region", { name: "Spent this month" });
    expect(within(month).getByText("71.20")).toBeInTheDocument();
    expect(within(month).getByText("of 100.00 USD")).toBeInTheDocument();
    expect(screen.getByText("41 300")).toBeInTheDocument();
    expect(within(await rowOf("Whole company")).getByText("71.20 USD")).toBeInTheDocument();
  });

  it("opens another node from the tree, with its limit source", async () => {
    const { user } = renderBudgets();
    await user.click(await rowOf("Jan Kowalski"));
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    expect(within(sidebar).getByText("Jan Kowalski")).toBeInTheDocument();
    expect(within(sidebar).getByRole("link", { name: "grant g-0420" })).toHaveAttribute("href", "/grants?sel=g-0420");
    expect(within(sidebar).queryByRole("button", { name: "Reset breaker" })).not.toBeInTheDocument();
    expect(within(sidebar).getByRole("link", { name: "Change limit…" })).toBeInTheDocument();
    expect(within(sidebar).getByRole("link", { name: "Requests in Traffic →" })).toHaveAttribute("href", "/traffic?q=j.kowalski");
  });

  it("closes the sidebar and keeps it closed", async () => {
    const { user } = renderBudgets();
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    await user.click(within(sidebar).getByRole("button", { name: /Close/ }));
    await waitFor(() => expect(screen.queryByRole("complementary", { name: "Budget" })).not.toBeInTheDocument());
  });

  it("resets the open breaker and shows the result inline", async () => {
    const { user } = renderBudgets();
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    await user.click(within(sidebar).getByRole("button", { name: "Reset breaker" }));
    expect(await within(sidebar).findByText("Breaker closed")).toBeInTheDocument();
    await waitFor(() => expect(within(sidebar).queryByRole("button", { name: "Reset breaker" })).not.toBeInTheDocument());
    expect(budgetNodes.items.find((n) => n.id === "session:s_77c1")?.breaker?.state).toBe("closed");
    expect(within(await rowOf("session s_77c1")).queryByText(/^open/)).not.toBeInTheDocument();
  });

  it("shows a reset error inline", async () => {
    server.use(http.post(adminPath("/budgets/breakers/:id/reset"), () => problem(403, "admins only")));
    const { user } = renderBudgets();
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    await user.click(within(sidebar).getByRole("button", { name: "Reset breaker" }));
    expect(await within(sidebar).findByRole("alert")).toHaveTextContent("admins only");
  });

  it("is read-only for viewers", async () => {
    renderBudgets(undefined, { user: VIEWER });
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    expect(within(sidebar).getByRole("button", { name: "Reset breaker" })).toBeDisabled();
    expect(within(sidebar).getByRole("button", { name: "Change limit…" })).toBeDisabled();
  });

  it("shows an error state when the tree cannot load", async () => {
    server.use(http.get(adminPath("/budgets"), () => problem(500, "budgets unavailable")));
    renderBudgets();
    expect(await screen.findByText("budgets unavailable")).toBeInTheDocument();
  });

  it("puts nodes with an unknown parent at the top level", () => {
    const nodes = [
      { id: "group:x", level: "group" as const, parent: "org", limits: {}, usage: {}, breaker: null },
      { id: "user:y", level: "user" as const, parent: "group:x", limits: {}, usage: {}, breaker: null },
    ];
    expect(flattenTree(nodes).map((r) => [r.node.id, r.depth])).toEqual([
      ["group:x", 0],
      ["user:y", 1],
    ]);
  });

  it("hides idle real-gateway sessions behind a toggle and shows short session ids", async () => {
    const real = (n: number) => ({
      id: `session:91dfc8100f170058:e2e-${n.toString(16).padStart(12, "0")}`,
      level: "session" as const,
      parent: "agent:research-bot",
      limits: {},
      usage: { usd_day: 0, usd_month: 0 },
      breaker: null,
    });
    const idle = [real(1), real(2), real(3)];
    const busy = { ...real(4), usage: { usd_day: 0.5, usd_month: 0.5 } };
    server.use(
      http.get(adminPath("/budgets"), () =>
        HttpResponse.json({
          nodes: [
            ...budgetNodes.items.filter((n) => n.id !== "session:s_77c1"),
            ...idle,
            busy,
          ],
        }),
      ),
    );
    const { user } = renderBudgets("?sel=agent:research-bot");
    await rowOf("research-bot");
    const table = screen.getByRole("table", { name: "Budget tree" });
    expect(within(table).getByText("session e2e-000000000004")).toBeInTheDocument();
    expect(within(table).queryByText(/e2e-000000000001/)).not.toBeInTheDocument();
    expect(within(table).queryByText(/91dfc8100f170058/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show 3 idle sessions" }));
    expect(within(table).getByText("session e2e-000000000001")).toBeInTheDocument();
    expect(within(table).getByText("session e2e-000000000001").closest("span[title]")).toHaveAttribute(
      "title",
      "91dfc8100f170058:e2e-000000000001",
    );
    await user.click(screen.getByRole("button", { name: "Hide idle sessions" }));
    expect(within(table).queryByText("session e2e-000000000001")).not.toBeInTheDocument();
  });

  it("shows the full session id in the sidebar and keeps a selected idle session visible", async () => {
    const node = {
      id: "session:91dfc8100f170058:e2e-1d9f1dfdffbd",
      level: "session" as const,
      parent: "agent:research-bot",
      limits: {},
      usage: {},
      breaker: null,
    };
    server.use(http.get(adminPath("/budgets"), () => HttpResponse.json({ generated_at: new Date().toISOString(), nodes: [...budgetNodes.items, node] })));
    renderBudgets(`?sel=${encodeURIComponent(node.id)}`);
    const sidebar = await screen.findByRole("complementary", { name: "Budget" });
    expect(within(sidebar).getByText("session e2e-1d9f1dfdffbd")).toBeInTheDocument();
    expect(within(sidebar).getByText("91dfc8100f170058:e2e-1d9f1dfdffbd")).toBeInTheDocument();
  });

  it("classifies idle sessions", () => {
    const base = { level: "session" as const, parent: null, limits: {}, usage: {}, breaker: null };
    expect(isIdleSession({ ...base, id: "session:a:b" })).toBe(true);
    expect(isIdleSession({ ...base, id: "session:a:b", usage: { gpu_seconds_day: 3 } })).toBe(false);
    expect(isIdleSession({ ...base, id: "session:a:b", limits: { usd_day: 1 } })).toBe(false);
    expect(
      isIdleSession({ ...base, id: "session:a:b", breaker: { id: "x", state: "open", reason: null, cooldown_until: null } as never }),
    ).toBe(false);
    expect(isIdleSession({ ...base, id: "user:a", level: "user" })).toBe(false);
    expect(shortSessionId({ ...base, id: "session:91dfc8100f170058:e2e-1" })).toBe("e2e-1");
    expect(shortSessionId({ ...base, id: "session:s_77c1" })).toBe("s_77c1");
  });
});
