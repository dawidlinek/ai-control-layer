import { expect, test } from "@playwright/test";

test.describe("traffic", () => {
  test("filters, opens a trace, follows it to the conversation and back", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/traffic");
    await expect(page.getByRole("heading", { level: 1, name: "Traffic" })).toBeVisible();

    const table = page.getByRole("table", { name: "Events" });
    const anna = table.locator('tr[data-row-id="evt_8f3a2c"]');
    await expect(anna).toContainText("Anna Nowak");
    await expect(anna).toContainText("SEC-PII-01");
    await expect(anna.getByLabel(/Session confidential since \d\d:\d\d · local only/)).toBeVisible();
    await expect(page.getByRole("button", { name: /Last 24 hours/ })).toBeVisible();

    // Hide allowed: in the URL, allowed rows gone.
    await expect(table.locator('tr[data-row-id="evt_8d5e10"]')).toBeVisible();
    await page.getByRole("switch", { name: "Hide allowed" }).click();
    await expect(page).toHaveURL(/hide=true/);
    await expect(table.locator('tr[data-row-id="evt_8d5e10"]')).toHaveCount(0);
    await expect(table.locator('[data-decision="allow"]')).toHaveCount(0);

    // Row click opens the trace sidebar.
    await anna.getByText("prompt").click();
    await expect(page).toHaveURL(/sel=tr_8f3a2c/);
    const trace = page.getByRole("complementary", { name: "Trace" });
    await expect(trace).toContainText("tr_8f3a2c");
    await expect(trace).toContainText("Anna Nowak’s prompt contained a PESEL, an IBAN and a name");
    await expect(page.getByTestId("model-saw").getByText("<PESEL_1>")).toBeVisible();
    const timeline = trace.getByRole("list", { name: "How the decision was made" });
    await expect(timeline).toContainText("PESEL found, checksum valid");
    await timeline.locator('li[data-step="classifier"]').getByRole("button").first().click();
    await expect(timeline).toContainText("0.97 ≥ 0.50");

    // Open the full conversation.
    await trace.getByRole("link", { name: /Open full conversation/ }).click();
    await expect(page).toHaveURL(/\/sessions\/c_51a8$/);
    await expect(page.getByRole("heading", { level: 1, name: "Conversation c_51a8" })).toBeVisible();
    const turns = page.getByRole("list", { name: "Turns" }).getByRole("listitem");
    await expect(turns).toHaveCount(6);
    await expect(page.getByText(/Session confidential since \d\d:\d\d · local only/)).toBeVisible();

    // And back to the trace in Traffic.
    await page.getByRole("link", { name: "Open trace tr_8f3a2c in Traffic" }).click();
    await expect(page).toHaveURL(/\/traffic\?sel=tr_8f3a2c/);
    await expect(page.getByRole("complementary", { name: "Trace" })).toContainText("tr_8f3a2c");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("complementary", { name: "Trace" })).toBeHidden();

    // Search by text.
    await page.getByRole("searchbox", { name: "Filter events" }).fill("litellm");
    await expect(page).toHaveURL(/q=litellm/);
    await expect(table.locator("tbody tr")).toHaveCount(1);
    await expect(table).toContainText("FEED-PKG-0007");
    expect(errors).toEqual([]);
  });

  test("an unknown session shows a friendly empty state", async ({ page }) => {
    await page.goto("/sessions/s_does_not_exist");
    await expect(page.getByText("This session is not in the audit log")).toBeVisible();
    await expect(page.getByRole("link", { name: "Back to Traffic" })).toBeVisible();
  });
});
