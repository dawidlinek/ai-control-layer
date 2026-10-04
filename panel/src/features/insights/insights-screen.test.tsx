import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { http } from "msw";
import { server } from "@/mocks/server";
import { adminPath, problem } from "@/mocks/handlers/helpers";
import { insightClusters } from "@/mocks/db/insights";
import { policyStatus } from "@/mocks/db/policy";
import { DEV_USER } from "@/lib/auth/user";
import { renderApp } from "@/test/render";
import { InsightsScreen } from "./insights-screen";
import { fillTemplate, howOften, placeholdersOf, timeItTakes } from "./model";

const VIEWER = { ...DEV_USER, role: "viewer" as const, roles: ["acl-viewer"] };

function renderInsights(search?: string, opts: Parameters<typeof renderApp>[1] = {}) {
  return renderApp(<InsightsScreen />, { searchParams: search, urlMemory: true, ...opts });
}

const sidebar = () => screen.findByRole("complementary", { name: "Repeated task" });

describe("InsightsScreen", () => {
  it("shows the privacy subtitle and the repeated tasks", async () => {
    renderInsights();
    expect(screen.getByRole("heading", { level: 1, name: "Automation Insights" })).toBeInTheDocument();
    expect(
      screen.getByText(
        "Found in masked prompts, on local models. Patterns used by fewer than 5 people are hidden. People see only their own suggestions.",
      ),
    ).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Repeated tasks" });
    const row = (await within(table).findByText("Explain a failing test and suggest a fix")).closest("tr")!;
    expect(within(row).getByText("developers")).toBeInTheDocument();
    expect(within(row).getByText("6")).toBeInTheDocument();
    expect(within(row).getByText("~14 times a day")).toBeInTheDocument();
    expect(within(row).getByText("~25 min a day")).toBeInTheDocument();
    expect(within(row).getByText("new")).toBeInTheDocument();
    const jira = within(table).getByText("Summarise this week’s Jira tickets").closest("tr")!;
    expect(within(jira).getByText("~1 h a week")).toBeInTheDocument();
    expect(within(jira).getByText("published")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Repeated tasks\s*4/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /Skills\s*2/ })).toBeInTheDocument();
  });

  it("drafts a skill, tries it with an example and publishes it as a new policy version", async () => {
    const { user } = renderInsights("?sel=ic-0101");
    const side = await sidebar();
    expect(within(side).getByText(/Developers paste pytest output/)).toBeInTheDocument();
    const draft = within(side).getByRole("region", { name: "Draft skill" });
    expect(within(draft).getByText("skill/explain-test-failure")).toBeInTheDocument();
    expect(within(draft).getByText("{test}")).toBeInTheDocument();
    expect(within(draft).getByText("{code}")).toBeInTheDocument();
    expect(within(draft).getByText("local/qwen3.8-27b")).toBeInTheDocument();
    expect(within(draft).getByText("preset balanced · no tools")).toBeInTheDocument();

    await user.click(within(side).getByRole("button", { name: "Try with an example" }));
    const example = within(side).getByRole("region", { name: "Example" });
    expect(within(example).getByText(/AssertionError: 0.0125 != 0.0124/)).toBeInTheDocument();
    expect(within(example).queryByText("{test}")).not.toBeInTheDocument();

    expect(within(side).getByRole("button", { name: "Dismiss" })).toBeDisabled();
    expect(within(side).getByRole("button", { name: "Dismiss" })).toHaveAttribute("title", expect.stringContaining("Not available"));

    await user.click(within(side).getByRole("button", { name: "Publish skill" }));
    const done = await within(side).findByRole("status");
    expect(done).toHaveTextContent("skill/explain-test-failure is live for developers");
    expect(done).toHaveTextContent("Saved as policy v9.");
    expect(policyStatus.version).toBe("v9");
    expect(insightClusters.items.find((c) => c.id === "ic-0101")?.status).toBe("published");
    await waitFor(() => expect(within(side).queryByRole("button", { name: "Publish skill" })).not.toBeInTheDocument());
    const row = within(screen.getByRole("table", { name: "Repeated tasks" })).getByText("Explain a failing test and suggest a fix").closest("tr")!;
    await waitFor(() => expect(within(row).getByText("published")).toBeInTheDocument());
    expect(screen.getByRole("tab", { name: /Skills\s*3/ })).toBeInTheDocument();
  });

  it("shows a publish error inline and keeps the draft", async () => {
    server.use(http.post(adminPath("/insights/clusters/:id/publish"), () => problem(409, "skill name already taken")));
    const { user } = renderInsights("?sel=ic-0103");
    const side = await sidebar();
    await user.click(within(side).getByRole("button", { name: "Publish skill" }));
    expect(await within(side).findByRole("alert")).toHaveTextContent("skill name already taken");
    expect(within(side).getByRole("button", { name: "Publish skill" })).toBeEnabled();
  });

  it("shows published tasks as published, without publish actions", async () => {
    renderInsights("?sel=ic-0102");
    const side = await sidebar();
    expect(within(side).getByRole("status")).toHaveTextContent("Published as skill/loan-memo-summary · used 212 times in 30 days");
    expect(within(side).queryByRole("button", { name: "Publish skill" })).not.toBeInTheDocument();
    expect(within(side).getByRole("region", { name: "Skill" })).toBeInTheDocument();
  });

  it("opens a task from the list", async () => {
    const { user } = renderInsights();
    const table = await screen.findByRole("table", { name: "Repeated tasks" });
    await user.click(await within(table).findByText("Translate client letters PL → EN"));
    const side = await sidebar();
    expect(within(side).getByText("skill/letter-pl-en")).toBeInTheDocument();
  });

  it("lists published skills with cost per run before → now", async () => {
    const { user } = renderInsights();
    await user.click(await screen.findByRole("tab", { name: /Skills/ }));
    const table = await screen.findByRole("table", { name: "Skills" });
    const loan = within(table).getByText("skill/loan-memo-summary").closest("tr")!;
    expect(within(loan).getByText("credit-analysts")).toBeInTheDocument();
    expect(within(loan).getByText("212")).toBeInTheDocument();
    expect(within(loan).getByText("3.9 GPU-s → 1.4 GPU-s")).toBeInTheDocument();
    expect(within(table).getByText("0.30 USD → 0.02 USD")).toBeInTheDocument();
  });

  it("is honest that local/loan-memo is prompt-configured, not fine-tuned", async () => {
    renderInsights("?tab=specialist");
    const spec = await screen.findByRole("region", { name: "Specialist models" });
    expect(within(spec).getByRole("heading", { name: "local/loan-memo" })).toBeInTheDocument();
    expect(within(spec).getByText(/prompt-configured on local\/qwen3.8-27b · not a fine-tuned model/)).toBeInTheDocument();
    expect(within(spec).getByText(/No model was trained or fine-tuned for it/)).toBeInTheDocument();
    const steps = within(within(spec).getByRole("list", { name: "Pipeline" })).getAllByRole("listitem");
    const trained = steps.find((s) => s.textContent?.includes("trained offline"))!;
    expect(trained).toHaveAttribute("data-state", "not done");
    expect(trained).toHaveTextContent("not used");
    expect(steps.find((s) => s.textContent?.includes("file scanned"))).toHaveAttribute("data-state", "not done");
    expect(steps.find((s) => s.textContent?.includes("used by auto"))).toHaveAttribute("data-state", "done");
    const evalTable = within(spec).getByRole("table", { name: "Evaluation" });
    expect(within(evalTable).getAllByRole("row")).toHaveLength(4);
    expect(within(spec).queryByText(/bielik/i)).not.toBeInTheDocument();
  });

  it("is read-only for viewers", async () => {
    renderInsights("?sel=ic-0101", { user: VIEWER });
    const side = await sidebar();
    const publish = within(side).getByRole("button", { name: "Publish skill" });
    expect(publish).toBeDisabled();
    expect(publish).toHaveAttribute("title", "Only admins can publish skills");
    expect(within(side).getByRole("button", { name: "Try with an example" })).toBeEnabled();
  });

  it("shows an error state when the clusters cannot load", async () => {
    server.use(http.get(adminPath("/insights/clusters"), () => problem(500, "insights unavailable")));
    renderInsights();
    expect(await screen.findByText("insights unavailable")).toBeInTheDocument();
  });

  it("derives how often, time and template parts", () => {
    const base = insightClusters.items[0];
    expect(howOften({ ...base, recurrence: "adhoc" })).toBe("now and then");
    expect(howOften({ ...base, recurrence: "daily", size: 30 })).toBe("every day");
    expect(timeItTakes({ ...base, est_minutes_per_day: 0 })).toBe("—");
    expect(placeholdersOf("Explain {test} for {code} and {test}")).toEqual(["test", "code"]);
    expect(fillTemplate("A {x} b", { x: "1" })).toEqual([{ text: "A " }, { name: "x", value: "1" }, { text: " b" }]);
  });
});
