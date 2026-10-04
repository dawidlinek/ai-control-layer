import { expect, test } from "@playwright/test";

test.describe("overview", () => {
  test("answers what is happening, are we safe and what it costs", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();

    const now = page.getByRole("region", { name: "What is happening?" });
    await expect(now.getByText("1 284")).toBeVisible();
    await expect(now.getByText("decisions · last 15 min")).toBeVisible();
    await expect(now.getByRole("img", { name: /stacked by decision/ })).toBeVisible();
    await expect(now.getByRole("link", { name: "block 44" })).toBeVisible();
    await expect(now.getByRole("list", { name: "Notable now" }).getByRole("listitem").first()).toBeVisible();

    const safe = page.getByRole("region", { name: "Are we safe?" });
    await expect(safe.getByRole("link", { name: /7\s*open incidents/ })).toBeVisible();
    await expect(safe.getByRole("list", { name: "Top risks" }).getByRole("link")).toHaveCount(5);

    const cost = page.getByRole("region", { name: "What is it costing?" });
    await expect(cost.getByText("/ 5.00 USD today")).toBeVisible();
    await expect(cost.getByText("1 912 / 3 600")).toBeVisible();
    await expect(cost.getByRole("table", { name: "Usage by model today" })).toContainText("local/loan-memo");

    await page.getByRole("group", { name: "Time range" }).getByRole("button", { name: "24h" }).click();
    await expect(page).toHaveURL(/range=24h/);
    await expect(now.getByText("decisions · last 24 h")).toBeVisible();

    await cost.getByRole("link", { name: "Open budgets →" }).click();
    await expect(page).toHaveURL(/\/budgets$/);
    expect(errors).toEqual([]);
  });

  test("a notable event opens its trace in Traffic", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("list", { name: "Notable now" }).getByRole("link", { name: /Anna Nowak/ }).click();
    await expect(page).toHaveURL(/\/traffic\?sel=tr_8f3a2c/);
  });
});
