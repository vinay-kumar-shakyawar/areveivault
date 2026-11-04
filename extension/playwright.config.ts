import { defineConfig } from "@playwright/test";

// Specs live in /e2e/extension; the config sits here so @playwright/test resolves from this package.
export default defineConfig({
  testDir: "../e2e/extension",
  testMatch: /.*\.spec\.ts/,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
});
