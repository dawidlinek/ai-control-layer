import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "@/mocks/server";
import { adminPath } from "@/mocks/handlers/helpers";
import { renderApp } from "@/test/render";
import { SidebarNav } from "./sidebar-nav";

describe("SidebarNav", () => {
  it("lists every screen under its section", () => {
    renderApp(<SidebarNav />);
    const nav = screen.getByRole("navigation", { name: "Main" });
    const labels = within(nav).getAllByRole("link").map((a) => a.textContent?.replace(/\d+$/, ""));
    expect(labels).toEqual([
      "Overview",
      "Traffic",
      "Incidents",
      "Approvals",
      "Users & groups",
      "Grants",
      "Policies",
      "Models & connectors",
      "Tools & MCP",
      "Known threats",
      "Budgets & spend",
      "Automation Insights",
    ]);
    for (const section of ["Monitor", "Access", "Govern", "Optimise"]) {
      expect(within(nav).getByText(section)).toHaveClass("uppercase", "text-[11px]", "font-bold");
    }
  });

  it("links to the documented routes", () => {
    renderApp(<SidebarNav />);
    const hrefs = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["/", "/traffic", "/incidents", "/approvals", "/users", "/grants", "/policies", "/models", "/tools", "/threats", "/budgets", "/insights"]);
  });

  it("marks the active item (accent tint, weight 600)", () => {
    renderApp(<SidebarNav />, { pathname: "/policies" });
    const active = screen.getByRole("link", { name: "Policies" });
    expect(active).toHaveAttribute("aria-current", "page");
    expect(active).toHaveClass("bg-accent-soft", "font-semibold");
    expect(screen.getByRole("link", { name: "Traffic" })).not.toHaveAttribute("aria-current");
  });

  it("keeps Traffic active on a session page and Overview only on /", () => {
    renderApp(<SidebarNav />, { pathname: "/sessions/s_9e21" });
    expect(screen.getByRole("link", { name: "Traffic" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });

  it("shows open incident and pending approval counts from the API", async () => {
    renderApp(<SidebarNav />);
    expect(await screen.findByLabelText("7 open")).toHaveTextContent("7");
    expect(await screen.findByLabelText("3 pending")).toHaveTextContent("3");
    expect(screen.getByRole("link", { name: /Incidents/ })).toContainElement(screen.getByLabelText("7 open"));
  });

  it("hides a badge when the count is zero", async () => {
    server.use(http.get(adminPath("/metrics/counts"), () => HttpResponse.json({ open_incidents: 7, pending_approvals: 0, quarantined_tools: 0 })));
    renderApp(<SidebarNav />);
    expect(await screen.findByLabelText("7 open")).toBeInTheDocument();
    expect(screen.queryByLabelText(/pending/)).not.toBeInTheDocument();
  });
});
