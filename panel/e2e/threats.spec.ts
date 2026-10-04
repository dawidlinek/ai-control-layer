import { expect, test } from "@playwright/test";

test.describe("known threats", () => {
  test("feed status, signature sidebar, sync and model files", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/threats");
    await expect(page.getByRole("heading", { level: 1, name: "Known threats" })).toBeVisible();

    const bar = page.getByRole("region", { name: "Signature feed" });
    await expect(bar.getByText("feed.corp:8080 · every 30 s")).toBeVisible();
    await expect(page.getByRole("button", { name: "+ Add rule" })).toBeDisabled();

    await page.getByRole("table", { name: "Signatures" }).getByText("FEED-PKG-0007").click();
    const side = page.getByRole("complementary", { name: "Signature" });
    await expect(side.getByLabel("Pattern")).toContainText("litellm == 1.82.7 | 1.82.8");
    await expect(side.getByRole("link", { name: "All in Traffic →" })).toHaveAttribute("href", "/traffic?rule=FEED-PKG-0007");

    await bar.getByRole("button", { name: "Sync now" }).click();
    await expect(page.getByText("Feed synced")).toBeVisible();

    await page.getByRole("tab", { name: /Model files/ }).click();
    const files = page.getByRole("table", { name: "Model files" });
    await files.getByText("finetune-v2.bin").click();
    await expect(page.getByRole("complementary", { name: "Model file" }).getByLabel("Technical detail")).toContainText("GLOBAL os.system");
    expect(errors).toEqual([]);
  });
});
