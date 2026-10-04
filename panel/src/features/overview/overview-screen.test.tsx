import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http } from "msw";
import { server } from "@/mocks/server";
import { adminPath, problem } from "@/mocks/handlers/helpers";
import { renderApp } from "@/test/render";
import { formatTokens, OverviewScreen } from "./overview-screen";

const card = (name: string) => screen.getByRole("region", { name });

describe("OverviewScreen", () => {
  it("shows what is happening in the last 15 minutes with legend totals", async () => {
    renderApp(<OverviewScreen />);
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    const now = card("What is happening?");
    expect(await within(now).findByText("1 284")).toBeInTheDocument();
    expect(within(now).getByText("decisions · last 15 min")).toBeInTheDocument();
    expect(within(now).getByRole("img", { name: /Decisions per minute, stacked by decision/ })).toBeInTheDocument();
    const legend = within(now).getByRole("list", { name: "Decisions by type" });
    expect(within(legend).getByRole("link", { name: "allow 1102" })).toHaveAttribute("href", "/traffic?decision=allow");
    expect(within(legend).getByRole("link", { name: "pseudonymise 71" })).toBeInTheDocument();
    expect(within(legend).getByRole("link", { name: "route_local 64" })).toBeInTheDocument();
    expect(within(legend).getByRole("link", { name: "require_approval 3" })).toBeInTheDocument();
    expect(within(legend).getByRole("link", { name: "block 44" })).toBeInTheDocument();
  });

  it("switches the range and keeps it in the URL", async () => {
    const onUrlUpdate = vi.fn();
    const { user } = renderApp(<OverviewScreen />, { urlMemory: true, onUrlUpdate });
    const now = card("What is happening?");
    await within(now).findByText("1 284");
    const range = screen.getByRole("group", { name: "Time range" });
    expect(within(range).getByRole("button", { name: "15m" })).toHaveAttribute("aria-pressed", "true");
    await user.click(within(range).getByRole("button", { name: "24h" }));
    expect(await within(now).findByText("decisions · last 24 h")).toBeInTheDocument();
    expect(within(range).getByRole("button", { name: "24h" })).toHaveAttribute("aria-pressed", "true");
    expect(onUrlUpdate).toHaveBeenLastCalledWith(expect.objectContaining({ queryString: "?range=24h" }));
  });

  it("reads the range from ?range=", async () => {
    renderApp(<OverviewScreen />, { searchParams: "?range=24h" });
    expect(await screen.findByText("decisions · last 24 h")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Decisions per hour/ })).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Time range" })).getByRole("button", { name: "24h" })).toHaveAttribute("aria-pressed", "true");
  });

  it("lists the last five non-allow events in Notable now, linking to their traces", async () => {
    renderApp(<OverviewScreen />);
    const list = await screen.findByRole("list", { name: "Notable now" });
    await waitFor(() => expect(within(list).getAllByRole("listitem").length).toBeGreaterThan(0));
    const items = within(list).getAllByRole("listitem");
    expect(items.length).toBeLessThanOrEqual(5);
    expect(within(list).queryByText(/Piotr’s general question/)).not.toBeInTheDocument(); // an allow
    const anna = within(list).getByRole("link", { name: /Anna Nowak’s prompt contained a PESEL/ });
    expect(anna).toHaveAttribute("href", "/traffic?sel=tr_8f3a2c");
    expect(within(anna).getByText("pseudonymise")).toBeInTheDocument();
    expect(within(anna).getByText("route_local")).toBeInTheDocument();
    expect(await within(list).findByText("Anna Nowak")).toBeInTheDocument(); // display name from /users
    expect(within(list).getAllByText("research-bot").length).toBeGreaterThan(0);
  });

  it("answers Are we safe? with open incidents by severity and the top risks", async () => {
    renderApp(<OverviewScreen />);
    const safe = card("Are we safe?");
    const count = await within(safe).findByRole("link", { name: /7\s*open incidents/ });
    expect(count).toHaveAttribute("href", "/incidents");
    expect(within(safe).getByRole("link", { name: "1 high" })).toHaveAttribute("href", "/incidents?severity=high");
    expect(within(safe).getByRole("link", { name: "2 medium" })).toBeInTheDocument();
    expect(within(safe).getByRole("link", { name: "4 low" })).toBeInTheDocument();
    const risks = await within(safe).findByRole("list", { name: "Top risks" });
    const links = within(risks).getAllByRole("link");
    expect(links).toHaveLength(5);
    expect(links[0]).toHaveTextContent("LLM02");
    expect(links[0]).toHaveTextContent("Sensitive information disclosure");
    expect(links[0]).toHaveTextContent("128");
    expect(links[0]).toHaveAttribute("href", "/traffic?q=LLM02");
    expect(links[4]).toHaveTextContent("Tool poisoning (rug pull)");
  });

  it("answers What is it costing? with spend, GPU time and usage by model", async () => {
    renderApp(<OverviewScreen />);
    const cost = card("What is it costing?");
    expect(await within(cost).findByText("3.12")).toBeInTheDocument();
    expect(within(cost).getByText("/ 5.00 USD today")).toBeInTheDocument();
    expect(within(cost).getByText("forecast 4.40 by 24:00")).toBeInTheDocument();
    expect(within(cost).getByText("62% used")).toBeInTheDocument();
    expect(within(cost).getByRole("meter", { name: "Spend today" })).toHaveAttribute("aria-valuenow", "3.12");
    expect(within(cost).getByText("1 912 / 3 600")).toBeInTheDocument();
    const table = within(cost).getByRole("table", { name: "Usage by model today" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(6);
    expect(within(table).getByText("1.92 USD")).toBeInTheDocument();
    expect(within(table).getByText("1 410 GPU-s")).toBeInTheDocument();
    expect(within(table).getByText("318k / 94k")).toBeInTheDocument();
    expect(within(table).queryByText(/bielik/i)).not.toBeInTheDocument();
    expect(within(cost).getByRole("link", { name: "Open budgets →" })).toHaveAttribute("href", "/budgets");
  });

  it("shows an error with retry when the summary fails", async () => {
    server.use(http.get(adminPath("/metrics/overview"), () => problem(500, "metrics unavailable")));
    renderApp(<OverviewScreen />);
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((a) => a.textContent?.includes("metrics unavailable"))).toBe(true);
  });

  it("has no posture score", async () => {
    renderApp(<OverviewScreen />);
    await screen.findByText("1 284");
    expect(screen.queryByText(/posture/i)).not.toBeInTheDocument();
  });

  it("formats token counts compactly", () => {
    expect(formatTokens(318_000)).toBe("318k");
    expect(formatTokens(1_420_000)).toBe("1.4M");
    expect(formatTokens(412)).toBe("412");
  });
});
