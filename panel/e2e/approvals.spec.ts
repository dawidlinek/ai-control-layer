import { expect, test } from "@playwright/test";

test.describe("approvals", () => {
  test("Jan's git push: read why it was held, approve once with a reason, badge drops to 2", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/approvals");
    await expect(page.getByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Waiting\s*3/ })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByText("Requests nobody answers are denied after 10 minutes")).toBeVisible();

    const table = page.getByRole("table", { name: "Approval requests" });
    await expect(table.getByRole("row")).toHaveCount(4);
    await table.getByRole("row").filter({ hasText: "apr-0193" }).click();
    await expect(page).toHaveURL(/sel=apr-0193/);

    const side = page.getByRole("complementary", { name: "Approval request" });
    await expect(side.getByText(/auto-deny in \d:\d\d/)).toBeVisible();
    await expect(side.getByText("git push origin feature/loan-calc")).toBeVisible();
    await expect(side.getByText("not a company remote")).toBeVisible();
    await expect(side.getByText("secret found")).toBeVisible();
    await expect(side.getByText('SCORING_API_KEY = "‹SECRET:api_key›"')).toBeVisible();
    await expect(side.getByRole("list", { name: "Reasons" }).getByRole("listitem")).toHaveCount(3);
    await expect(side.getByRole("link", { name: "Open full session s_9e21 →" })).toHaveAttribute("href", "/sessions/s_9e21");

    await side.getByRole("button", { name: "Approve once" }).click();
    await expect(side.getByText("Write a reason to approve.")).toBeVisible();
    await side.getByLabel("Reason (required to approve)").fill("pushes to a private remote");
    await side.getByRole("button", { name: "Approve once" }).click();
    await expect(side.getByRole("status").filter({ hasText: "Approved once" })).toBeVisible();

    await expect(table.getByRole("row").filter({ hasText: "apr-0193" })).toContainText("approved");
    await expect(page.getByRole("navigation", { name: "Main" }).getByLabel("2 pending")).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("deny is the primary action and an elevation explains where it shows", async ({ page }) => {
    await page.goto("/approvals?sel=apr-0195");
    const side = page.getByRole("complementary", { name: "Approval request" });
    await expect(side.getByText("terraform apply -auto-approve")).toBeVisible();
    await side.getByRole("button", { name: "Deny" }).click();
    await expect(side.getByText("Denied", { exact: true })).toBeVisible();

    await page.goto("/approvals?sel=apr-0193");
    await side.getByLabel("Reason (required to approve)").fill("checked the remote with Jan");
    await side.getByRole("button", { name: "5m" }).click();
    await side.getByRole("button", { name: "Approve for 5 minutes" }).click();
    await expect(side.getByText("It shows as an elevation on Jan Kowalski’s access page.", { exact: false })).toBeVisible();
  });

  test("decided tab lists the last 24 h", async ({ page }) => {
    await page.goto("/approvals?tab=decided");
    const table = page.getByRole("table", { name: "Approval requests" });
    await expect(table.getByRole("row")).toHaveCount(4);
    await expect(table.getByText("apr-0188")).toBeVisible();
  });
});
