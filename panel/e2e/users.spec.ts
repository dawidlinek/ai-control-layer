import { expect, test } from "@playwright/test";

test.describe("users & groups", () => {
  test("People: grant a cloud model to a person inline", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/users");
    await expect(page.getByRole("heading", { level: 1, name: "Users & groups" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "People 41" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Groups 4" })).toBeVisible();

    await page.getByRole("table", { name: "People" }).getByText("Piotr Zieliński").click();
    await expect(page).toHaveURL(/sel=p\.zielinski/);
    const side = page.getByRole("complementary", { name: "Person" });
    const access = side.getByRole("list", { name: "Access" });
    await access.getByRole("button", { name: "Grant smart → gemini" }).click();

    const form = side.getByRole("form", { name: "Grant access" });
    await expect(form.getByText("× confidential · LOCK-01")).toBeVisible();
    await form.getByRole("button", { name: "Grant access" }).click();
    await expect(form.getByText("A reason is required (at least 3 characters).")).toBeVisible();
    await form.getByLabel(/^Reason \(required\)/).fill("Gemini pilot");
    await form.getByRole("button", { name: "Grant access" }).click();

    await expect(side.getByText(/^Piotr can use smart → gemini until/)).toBeVisible();
    await expect(side.getByRole("list", { name: "Their clients see" }).getByText(/smart\s*\(new\)/)).toBeVisible();
    await expect(access.getByText(/grant g-0422 · “Gemini pilot” · ≤ internal/)).toBeVisible();
    await expect(side.getByRole("link", { name: "Grant history →" })).toHaveAttribute("href", "/grants?q=p.zielinski");
    expect(errors).toEqual([]);
  });

  test("Groups: change a group's models, tools and budget and save as policy v9", async ({ page }) => {
    await page.goto("/users?tab=groups");
    await page.getByRole("table", { name: "Groups" }).getByText("developers").click();
    const side = page.getByRole("complementary", { name: "Group" });
    await expect(side.getByText(/^Keycloak group/)).toContainText("14 members");

    await side.getByRole("switch", { name: /smart \(gemini\)/ }).click();
    await side.getByRole("switch", { name: "bash", exact: true }).click();
    await side.getByRole("button", { name: "Raise budget" }).click();

    const bar = side.getByRole("region", { name: "Unsaved changes" });
    await expect(bar).toContainText("3 changes: + smart (gemini), − bash, budget 5 → 6 USD");
    await bar.getByRole("button", { name: "Save as policy v9" }).click();
    await expect(side.getByText("v9 is live.")).toBeVisible();
    await expect(page.getByRole("table", { name: "Groups" }).getByText("auto · fast · local · smart")).toBeVisible();
  });
});
