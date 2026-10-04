import { expect, test } from "@playwright/test";

const ROUTES: Array<[string, string]> = [
  ["/", "Overview"],
  ["/traffic", "Traffic"],
  ["/incidents", "Incidents"],
  ["/approvals", "Approvals"],
  ["/users", "Users & groups"],
  ["/grants", "Grants"],
  ["/policies", "Policies"],
  ["/models", "Models & connectors"],
  ["/tools", "Tools & MCP"],
  ["/threats", "Known threats"],
  ["/budgets", "Budgets & spend"],
  ["/insights", "Automation Insights"],
];

test.describe("shell", () => {
  test("renders the top bar, the navigation and the count badges from the mock API", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("banner").getByText("Rogatka")).toBeVisible();
    await expect(page.getByRole("banner").getByText("Dashboard")).toBeVisible();
    const profile = page.getByRole("button", { name: "Account menu" });
    await expect(profile).toContainText("Katarzyna Wójcik");
    await expect(profile).toContainText("Security analyst");

    const nav = page.getByRole("navigation", { name: "Main" });
    for (const [, label] of ROUTES) await expect(nav.getByRole("link", { name: label })).toBeVisible();
    await expect(nav.getByLabel("7 open")).toBeVisible();
    await expect(nav.getByLabel("3 pending")).toBeVisible();
    await expect(nav.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  });

  for (const [route, title] of ROUTES) {
    test(`${route} loads`, async ({ page }) => {
      const errors: string[] = [];
      page.on("pageerror", (e) => errors.push(e.message));
      await page.goto(route);
      await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
      await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: title })).toHaveAttribute("aria-current", "page");
      expect(errors).toEqual([]);
    });
  }

  test("a session page loads", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/sessions/c_51a8");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("navigates by clicking the sidebar", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Incidents" }).click();
    await expect(page).toHaveURL(/\/incidents$/);
    await expect(page.getByRole("heading", { level: 1, name: "Incidents" })).toBeVisible();
  });

  test("the profile menu shows the account and the shortcuts dialog opens", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Account menu" }).click();
    const menu = page.getByRole("menu");
    await expect(menu.getByText("k.wojcik@corp.example")).toBeVisible();
    await expect(menu.getByText("acl-admin")).toBeVisible();
    await menu.getByRole("menuitem", { name: /Keyboard shortcuts/ }).click();
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("g then i goes to Incidents", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await page.keyboard.press("g");
    await page.keyboard.press("i");
    await expect(page).toHaveURL(/\/incidents$/);
  });

  test("theme switch persists across reload without a flash", async ({ page }) => {
    await page.goto("/");
    const html = page.locator("html");
    // Light is the default (no cookie).
    await expect(html).toHaveAttribute("data-theme", "light");
    const lightBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);

    await page.getByRole("button", { name: "Account menu" }).click();
    await page.getByRole("group", { name: "Theme" }).getByRole("button", { name: "Dark" }).click();
    await expect(html).toHaveAttribute("data-theme", "dark");
    const darkBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(darkBg).not.toBe(lightBg);

    await page.reload({ waitUntil: "commit" });
    // The server renders the attribute from the cookie: it is right before any script runs.
    await expect(html).toHaveAttribute("data-theme", "dark");
    await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(darkBg);

    await page.getByRole("button", { name: "Account menu" }).click();
    await page.getByRole("group", { name: "Theme" }).getByRole("button", { name: "Light" }).click();
    await page.reload();
    await expect(html).toHaveAttribute("data-theme", "light");
  });

  test("dev mode: ?role=viewer shows the viewer role", async ({ page }) => {
    await page.goto("/?role=viewer");
    await expect(page.getByRole("button", { name: "Account menu" })).toContainText("Viewer");
  });

  test("the navigation stacks above the content on a phone-width screen", async ({ page }) => {
    await page.setViewportSize({ width: 600, height: 900 });
    await page.goto("/");
    const nav = await page.getByRole("navigation", { name: "Main" }).boundingBox();
    const main = await page.getByRole("main").boundingBox();
    expect(nav && main && main.y >= nav.y + nav.height - 1).toBe(true);
  });

  test("signing out of the demo goes to the signed-out page", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Account menu" }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/signed-out$/);
    await expect(page.getByRole("heading", { name: "You are signed out" })).toBeVisible();
  });
});
