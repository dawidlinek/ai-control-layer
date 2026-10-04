import { expect, test } from "@playwright/test";

test.describe("policies", () => {
  test("threshold change → impact → publish as v9 → live, then YAML and History show it", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/policies");
    await expect(page.getByRole("heading", { level: 1, name: "Policies" })).toBeVisible();
    const live = page.getByTestId("policy-live");
    await expect(live).toHaveText(/live v8 · loaded \d\d:\d\d from the file \(edited on disk\)/);

    // Rules: open SEC-PI-01.
    const rules = page.getByRole("table", { name: "Rules" });
    await rules.getByRole("row").filter({ hasText: "SEC-PI-01" }).click();
    await expect(page).toHaveURL(/rule=SEC-PI-01/);
    const rule = page.getByRole("complementary", { name: "Rule" });
    await expect(rule.getByText("Block when the injection score is at least")).toBeVisible();

    // Raise the threshold: the dry-run impact appears.
    await rule.getByRole("button", { name: "Raise" }).click();
    await expect(rule.getByLabel("Injection threshold")).toHaveText("0.85");
    const box = rule.getByRole("form", { name: "If you publish this" });
    await expect(box.getByText("Would have let through 3 of the last 500 requests that were blocked.")).toBeVisible();
    await expect(box).toContainText("2.1% → 3.5%");
    await expect(box).toContainText("142 / 144 pass");

    // Publish with a note.
    await box.getByRole("textbox", { name: "Note for history" }).fill("Fewer false alarms for developers");
    await box.getByRole("button", { name: "Publish as v9" }).click();
    await expect(rule.getByText("v9 is live")).toBeVisible();
    await expect(live).toHaveText("live v9 · published from the panel just now by you");

    // Org-locked rules are read-only.
    await rules.getByRole("row").filter({ hasText: "SEC-SECRET-01" }).click();
    await expect(rule.getByText(/Org lock LOCK-02/)).toBeVisible();
    await expect(rule.getByRole("button", { name: "Raise" })).toHaveCount(0);

    // YAML: Monaco loads controls.yaml with the selected rule's line highlighted.
    await rule.getByRole("button", { name: "Open in YAML" }).click();
    await expect(page).toHaveURL(/tab=yaml/);
    const editor = page.getByRole("group", { name: "controls.yaml editor" });
    await expect(editor.locator(".monaco-editor")).toBeVisible();
    await expect(editor.locator(".view-lines")).toContainText("SEC-SECRET-01");
    await expect(editor.locator(".rg-yaml-sel")).toHaveCount(1);
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(page.getByText("No problems found")).toBeVisible();

    // History: v9 from the panel, with its diff.
    await page.getByRole("tab", { name: "History" }).click();
    const versions = page.getByRole("table", { name: "Versions" });
    const v9 = versions.getByRole("row").filter({ hasText: "v9" });
    await expect(v9).toContainText("panel");
    await expect(v9).toContainText("Fewer false alarms for developers");
    await v9.click();
    const version = page.getByRole("complementary", { name: "Version" });
    await expect(version.getByRole("list", { name: "Changes in controls.yaml" })).toContainText("injection_threshold: 0.85");
    await expect(version.getByText("This is the live version.")).toBeVisible();

    expect(errors).toEqual([]);
  });

  test("rolls back to an older version", async ({ page }) => {
    await page.goto("/policies?tab=history&sel=6");
    const version = page.getByRole("complementary", { name: "Version" });
    await version.getByRole("button", { name: "Roll back to this version…" }).click();
    const dialog = page.getByRole("dialog", { name: "Roll back to v6?" });
    await dialog.getByRole("textbox", { name: "Reason (required)" }).fill("Undo the threshold change");
    await dialog.getByRole("button", { name: "Roll back to v6" }).click();
    await expect(dialog).toBeHidden();
    await expect(version.getByText("v9 is live")).toBeVisible();
    await expect(page.getByTestId("policy-live")).toHaveText("live v9 · rolled back just now by you");
  });

  test("viewers can read but not publish", async ({ page }) => {
    await page.goto("/policies?rule=SEC-PI-01&role=viewer");
    const rule = page.getByRole("complementary", { name: "Rule" });
    await expect(rule.getByText("Block when the injection score is at least")).toBeVisible();
    await expect(rule.getByRole("button", { name: "Raise" })).toBeDisabled();
    await expect(rule.getByText(/Only admins can change policy/)).toBeVisible();
  });
});
