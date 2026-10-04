import { expect, test } from "@playwright/test";

test.describe("budgets", () => {
  test("opens on the research-bot session with the open breaker and resets it", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/budgets");
    await expect(page.getByRole("heading", { level: 1, name: "Budgets & spend" })).toBeVisible();
    await expect(page.getByRole("region", { name: "Spent today" })).toContainText("3.12");

    const tree = page.getByRole("table", { name: "Budget tree" });
    await expect(tree.getByRole("row")).toHaveCount(11);
    await expect(tree.getByRole("row", { name: /session s_77c1/ })).toContainText(/open · \d:\d\d/);

    const sidebar = page.getByRole("complementary", { name: "Budget" });
    await expect(sidebar).toContainText("session s_77c1");
    await expect(sidebar.getByText("Breaker open.")).toBeVisible();
    await expect(sidebar.getByRole("list", { name: "By model" })).toContainText("local/qwen3.8-27b");

    await sidebar.getByRole("button", { name: "Reset breaker" }).click();
    await expect(sidebar.getByText("Breaker closed")).toBeVisible();
    await expect(tree.getByRole("row", { name: /session s_77c1/ })).not.toContainText("open ·");

    await page.getByRole("group", { name: "Period" }).getByRole("button", { name: "This month" }).click();
    await expect(page).toHaveURL(/period=month/);
    await expect(page.getByRole("region", { name: "Spent this month" })).toContainText("71.20");

    await tree.getByRole("row", { name: /Jan Kowalski/ }).click();
    await expect(page).toHaveURL(/sel=user/);
    await expect(sidebar.getByRole("link", { name: "grant g-0420" })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("viewers cannot reset a breaker", async ({ page }) => {
    await page.goto("/budgets?role=viewer");
    await expect(page.getByRole("complementary", { name: "Budget" }).getByRole("button", { name: "Reset breaker" })).toBeDisabled();
  });
});
