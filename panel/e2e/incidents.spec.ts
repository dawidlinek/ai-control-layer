import { expect, test } from "@playwright/test";

test.describe("incidents", () => {
  test("triage the docs-search rug pull: evidence, assign to me, note, status", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/incidents");
    await expect(page.getByRole("heading", { level: 1, name: "Incidents" })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Open\s*7/ })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tab", { name: /Resolved\s*2/ })).toBeVisible();
    await expect(page.getByRole("tab", { name: /All\s*9/ })).toBeVisible();

    const table = page.getByRole("table", { name: "Incidents" });
    await expect(table.getByRole("row")).toHaveCount(8);
    await table.getByRole("row").filter({ hasText: "inc-0057" }).click();
    await expect(page).toHaveURL(/sel=inc-0057/);

    const side = page.getByRole("complementary", { name: "Incident" });
    await expect(side.getByText("docs-search › search_docs")).toBeVisible();
    await expect(side.getByText("hidden instruction")).toBeVisible();
    await expect(side.getByText(/0 calls since the change/)).toBeVisible();
    await expect(side.getByRole("button", { name: "Keep quarantined and close" })).toBeVisible();

    await side.getByRole("button", { name: "Assign to me" }).click();
    await expect(side.getByText("k.wojcik (you)")).toBeVisible();

    await side.getByRole("textbox", { name: "Add a note" }).fill("asked the vendor about the change");
    await side.getByRole("button", { name: "Add" }).click();
    await expect(side.getByRole("list", { name: "Timeline" })).toContainText("asked the vendor about the change");

    await side.getByRole("button", { name: "Status: Open" }).click();
    await page.getByRole("menuitemradio", { name: "Triaged" }).click();
    await expect(side.getByRole("button", { name: "Status: Triaged" })).toBeVisible();
    await expect(table.getByRole("row").filter({ hasText: "inc-0057" })).toContainText("Triaged");

    await page.getByRole("switch", { name: "Assigned to me" }).click();
    await expect(table.getByRole("row")).toHaveCount(3); // header + inc-0058 + inc-0057
    expect(errors).toEqual([]);
  });

  test("the research-bot budget breach shows the open breaker", async ({ page }) => {
    await page.goto("/incidents?sel=inc-0058");
    const side = page.getByRole("complementary", { name: "Incident" });
    await expect(side.getByText("OPEN", { exact: true })).toBeVisible();
    await expect(side.getByText(/half-open in \d:\d\d/)).toBeVisible();
    await expect(side.getByRole("meter", { name: "GPU-seconds, session s_77c1" })).toBeVisible();
    await expect(side.getByText("120 / 120")).toBeVisible();
    await expect(side.getByRole("link", { name: "BUDGET-LOOP-01" })).toBeVisible();
  });

  test("viewers read only", async ({ page }) => {
    await page.goto("/incidents?role=viewer&sel=inc-0057");
    const side = page.getByRole("complementary", { name: "Incident" });
    await expect(side.getByText("docs-search › search_docs")).toBeVisible();
    await expect(side.getByRole("button", { name: "Assign to me" })).toHaveCount(0);
    await expect(side.getByRole("button", { name: "Keep quarantined and close" })).toBeDisabled();
  });
});
