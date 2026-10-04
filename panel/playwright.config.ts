import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.E2E_PORT ?? 3100);

/**
 * E2E runs against `pnpm dev` in mock mode (MSW answers the admin API, demo user is signed in), chromium only.
 * Install the browser once with `pnpm exec playwright install chromium`.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 180_000, // the first request to a route compiles it in dev mode
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // Optional: use a pre-installed Chromium instead of the Playwright download (e.g. cloud containers).
        launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } : {},
      },
    },
  ],
  webServer: {
    command: "pnpm dev",
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    env: {
      PORT: String(PORT),
      NEXT_PUBLIC_API_MOCKING: "enabled",
      ROGATKA_AUTH: "dev",
      NEXT_TELEMETRY_DISABLED: "1",
    },
  },
});
