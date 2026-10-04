import { expect, test } from "@playwright/test";

test.describe("insights", () => {
  test("drafts, tries and publishes a skill, then shows it under Skills", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/insights");
    await expect(page.getByRole("heading", { level: 1, name: "Automation Insights" })).toBeVisible();
    await expect(page.getByText(/Patterns used by fewer than 5 people are hidden/)).toBeVisible();

    await page.getByRole("table", { name: "Repeated tasks" }).getByText("Explain a failing test and suggest a fix").click();
    const sidebar = page.getByRole("complementary", { name: "Repeated task" });
    await expect(sidebar.getByText("skill/explain-test-failure").first()).toBeVisible();

    await sidebar.getByRole("button", { name: "Try with an example" }).click();
    await expect(sidebar.getByRole("region", { name: "Example" })).toContainText("AssertionError");

    await sidebar.getByRole("button", { name: "Publish skill" }).click();
    await expect(sidebar.getByRole("status")).toContainText("skill/explain-test-failure is live for developers");
    await expect(sidebar.getByRole("status")).toContainText(/Saved as policy v\d+/);

    await page.getByRole("tab", { name: /Skills/ }).click();
    await expect(page.getByRole("table", { name: "Skills" })).toContainText("skill/explain-test-failure");

    await page.getByRole("tab", { name: /Specialist models/ }).click();
    const spec = page.getByRole("region", { name: "Specialist models" });
    await expect(spec).toContainText("not a fine-tuned model");
    await expect(spec.getByRole("table", { name: "Evaluation" })).toBeVisible();
    expect(errors).toEqual([]);
  });
});
