import { expect, test } from "@playwright/test";

test.describe("grants", () => {
  test("filters, opens a grant and revokes it", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/grants");
    await expect(page.getByRole("heading", { level: 1, name: "Grants" })).toBeVisible();
    const table = page.getByRole("table", { name: "Grants" });
    await expect(table.getByText("model smart → gemini")).toBeVisible();

    await page.getByRole("button", { name: /^Denials/ }).click();
    await expect(table.getByText("tool bash")).toBeVisible();
    await expect(table.getByText("model smart → gemini")).toHaveCount(0);
    await page.getByRole("button", { name: /^Active/ }).click();

    await table.getByText("model smart → gemini").click();
    const side = page.getByRole("complementary", { name: "Grant" });
    await expect(side.getByText(/Jan Kowalski may use the cloud model smart \(Gemini\)/)).toBeVisible();
    await expect(side.getByText(/Ceiling: LOCK-01/)).toBeVisible();
    await expect(side.getByRole("link", { name: "Open person →" })).toHaveAttribute("href", "/users?sel=j.kowalski");

    await side.getByRole("button", { name: "Revoke" }).click();
    await side.getByLabel(/^Reason \(required\)/).fill("pilot ended");
    await side.getByRole("form", { name: "Revoke grant" }).getByRole("button", { name: "Revoke grant" }).click();
    await expect(side.getByText("Revoked", { exact: true })).toBeVisible();
    await expect(side.getByRole("button", { name: "Grant again…" })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("new grant: the LOCK-01 ceiling check, then Create grant", async ({ page }) => {
    await page.goto("/grants");
    await page.getByRole("button", { name: "+ New grant" }).click();
    const form = page.getByRole("form", { name: "New grant" });
    await form.getByLabel("Person or group").selectOption("user:e.grabowska");
    await form.getByRole("checkbox", { name: "confidential" }).click();
    await expect(form.getByRole("alert")).toContainText("Blocked by LOCK-01");
    await expect(form.getByRole("button", { name: "Create grant" })).toBeDisabled();
    await form.getByRole("checkbox", { name: "confidential" }).click();
    await form.getByLabel(/^Reason \(required\)/).fill("Gemini pilot for reports");
    await form.getByRole("button", { name: "Create grant" }).click();

    const side = page.getByRole("complementary", { name: "Grant" });
    await expect(side.getByText("Grant g-0422 created")).toBeVisible();
    await expect(page.getByRole("table", { name: "Grants" }).getByText("Ewa Grabowska")).toBeVisible();
  });
});
