import { expect, test } from "@playwright/test";

test.describe("models & connectors", () => {
  test("connector cards, model sidebar and the Gemini kill switch", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/models");
    await expect(page.getByRole("heading", { level: 1, name: "Models & connectors" })).toBeVisible();

    const gemini = page.getByRole("region", { name: "Gemini connector" });
    await expect(gemini.getByText("healthy")).toBeVisible();
    const table = page.getByRole("table", { name: "Models" });
    await expect(table.getByText("gemini/flash")).toBeVisible();
    await expect(table.getByText("local/qwen3.8-27b")).toBeVisible();
    await expect(page.getByRole("table", { name: "Guard models" }).getByText("Injection classifier")).toBeVisible();

    await table.getByText("gemini/flash").click();
    await expect(page).toHaveURL(/sel=gemini%2Fflash|sel=gemini\/flash/);
    const side = page.getByRole("complementary", { name: "Model" });
    await expect(side.getByText("How auto picks it")).toBeVisible();
    await expect(side.getByText("41%")).toBeVisible();

    await page.getByRole("switch", { name: "Gemini on" }).click();
    const dialog = page.getByRole("dialog", { name: "Switch off Gemini?" });
    await dialog.getByRole("button", { name: "Switch off Gemini" }).click();
    await expect(dialog.getByText(/Write a reason/)).toBeVisible();
    await dialog.getByLabel("Reason (required)").fill("provider incident drill");
    await dialog.getByRole("button", { name: "Switch off Gemini" }).click();

    await expect(page.getByRole("status").filter({ hasText: "Gemini is switched off." })).toContainText(
      "now go to local models and their answers are marked as degraded. Saved as policy v9.",
    );
    await expect(page.getByRole("switch", { name: "Gemini on" })).not.toBeChecked();
    await expect(table.getByText(/default for normal work · off/)).toBeVisible();
    expect(errors).toEqual([]);
  });
});
