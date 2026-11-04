/**
 * Extension E2E: loads the E2E build of the unpacked extension into Chromium,
 * seeds a local vault through the E2E-only service-worker hook (no server), and
 * exercises autofill, phishing defenses and save/update prompts against fixture sites.
 */
import { chromium, expect, test as base, type BrowserContext, type Frame, type Page, type Worker } from "@playwright/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error - plain ESM fixture module
import { HTTPS_PORT, HTTP_PORT, startServers } from "./fixtures/server.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const EXT = resolve(here, "../../extension/dist/chrome");
const LEGIT = `https://arevei-test.com:${HTTPS_PORT}`;
const SEED = [{ title: "Arevei Test", url: "https://arevei-test.com", username: "me@arevei-test.com", password: "Correct-Password-1" }];

type Fixtures = { ctx: BrowserContext; sw: Worker; page: Page };

const test = base.extend<Fixtures, { servers: void }>({
  servers: [
    async ({}, use) => {
      const stop = await startServers();
      await use();
      await stop();
    },
    { scope: "worker", auto: true },
  ],
  ctx: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "arevei-e2e-"));
    const ctx = await chromium.launchPersistentContext(userDataDir, {
      // Playwright 1.48's headless shell can't load extensions; Chrome's new headless mode can.
      headless: false,
      ignoreHTTPSErrors: true,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`,
        "--host-resolver-rules=MAP * 127.0.0.1",
        "--ignore-certificate-errors",
        "--headless=new",
      ],
    });
    await use(ctx);
    await ctx.close();
    rmSync(userDataDir, { recursive: true, force: true });
  },
  sw: async ({ ctx }, use) => {
    const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"));
    // The worker may be registered before its module has finished evaluating.
    await expect.poll(() => sw.evaluate(() => typeof (self as any).__e2eSeed)).toBe("function");
    await sw.evaluate(async (items) => (self as any).__e2eSeed(items), SEED);
    await use(sw);
  },
  page: async ({ ctx, sw }, use, testInfo) => {
    const workers: string[] = [];
    ctx.on("serviceworker", (w) => workers.push(w.url()));
    const page = ctx.pages()[0] ?? (await ctx.newPage());
    await use(page);
    if (testInfo.status !== testInfo.expectedStatus) {
      const cur = ctx.serviceWorkers()[0];
      const info = cur ? await cur.evaluate(() => ({ boot: (self as any).__e2eBootedAt, locks: (self as any).__e2eLockCount })) : null;
      console.log("DBG sw restarts:", workers.length, "same worker:", cur === sw, "info:", JSON.stringify(info));
    }
  },
});

/** Click the inline icon drawn at the right edge of a field (a real, trusted click). */
async function clickIcon(page: Page, box: { x: number; y: number; width: number; height: number }) {
  await page.mouse.click(box.x + box.width - 6 - 10, box.y + box.height / 2);
}

async function frameMatching(page: Page, part: string): Promise<Frame> {
  let found: Frame | undefined;
  await expect.poll(() => (found = page.frames().find((f) => !f.isDetached() && f.url().includes(part))) !== undefined, { timeout: 10_000 }).toBe(true);
  return found!;
}

async function openMenuFor(page: Page, selector: string): Promise<Frame> {
  const box = await page.locator(selector).boundingBox();
  expect(box).not.toBeNull();
  await expect(page.locator("[data-arevei-icon]").first()).toBeAttached();
  await clickIcon(page, box!);
  const menu = await frameMatching(page, "/menu.html");
  await menu.waitForSelector(".menu-head");
  await expect(menu.locator("body")).not.toContainText("Loading"); // extension CSP forbids eval-based waits
  return menu;
}

test("inline icon appears, nothing fills on load, click fills on the legit site", async ({ page }) => {
  await page.goto(`${LEGIT}/login.html`);
  await expect(page.locator("[data-arevei-icon]").first()).toBeAttached();
  await page.waitForTimeout(1500);
  await expect(page.locator("#username")).toHaveValue("");
  await expect(page.locator("#password")).toHaveValue("");

  const menu = await openMenuFor(page, "#password");
  await expect(menu.locator("button.item")).toHaveCount(1);
  await expect(menu.locator("button.item .title")).toHaveText("Arevei Test");
  await menu.locator("button.item").click();
  await expect(page.locator("#username")).toHaveValue("me@arevei-test.com");
  await expect(page.locator("#password")).toHaveValue("Correct-Password-1");
});

test("hidden/transparent/offscreen trap fields are never filled", async ({ page }) => {
  await page.goto(`${LEGIT}/trap.html`);
  const menu = await openMenuFor(page, "#password");
  await menu.locator("button.item").click();
  await expect(page.locator("#password")).toHaveValue("Correct-Password-1");
  for (const id of ["#trap-hidden", "#trap-transparent", "#trap-offscreen"]) await expect(page.locator(id)).toHaveValue("");
});

for (const [name, host] of [
  ["Cyrillic homograph", "xn--revei-test-yqi.com"],
  ["embedded real domain", "arevei-test.com.evil.test"],
  ["typosquat", "arevel-test.com"],
] as const) {
  test(`no matches and no fill on lookalike: ${name}`, async ({ page }) => {
    await page.goto(`https://${host}:${HTTPS_PORT}/login.html`);
    const menu = await openMenuFor(page, "#password");
    await expect(menu.locator(".banner.danger")).toContainText("phishing");
    await expect(menu.locator("button.item")).toHaveCount(0);
    await expect(page.locator("#username")).toHaveValue("");
    await expect(page.locator("#password")).toHaveValue("");
  });
}

test("cross-origin iframe on another site gets no matches and no fill", async ({ page }) => {
  await page.goto(`https://other-site.com:${HTTPS_PORT}/frame-host.html`);
  const frame = page.frameLocator("#frame");
  await expect(frame.locator("#password")).toBeVisible();
  const box = await frame.locator("#password").boundingBox();
  await page.waitForTimeout(500);
  await clickIcon(page, box!);
  const menu = await frameMatching(page, "/menu.html");
  await expect(menu.locator("body")).not.toContainText("Loading"); // extension CSP forbids eval-based waits
  await expect(menu.locator("button.item")).toHaveCount(0);
  await expect(menu.locator("body")).toContainText("embedded from another site");
  await expect(frame.locator("#password")).toHaveValue("");
});

test("HTTP page warns and requires explicit confirmation before filling", async ({ page }) => {
  await page.goto(`http://arevei-test.com:${HTTP_PORT}/login.html`);
  const menu = await openMenuFor(page, "#password");
  await expect(menu.locator(".banner.warning")).toContainText("not secure");
  await menu.locator("button.item").click();
  await expect(menu.locator("button.item .sub")).toContainText("Click again");
  await expect(page.locator("#password")).toHaveValue("");
  await menu.locator("button.item").click();
  await expect(page.locator("#password")).toHaveValue("Correct-Password-1");
});

test("submitting a new login shows the save prompt and saves", async ({ page, sw }) => {
  await page.goto(`https://newsite-test.com:${HTTPS_PORT}/login.html`);
  await page.fill("#username", "new@user.com");
  await page.fill("#password", "Brand-New-Pass-42");
  await page.click("#submit");
  await expect(page.locator("#done")).toBeVisible();
  const prompt = await frameMatching(page, "/prompt.html");
  await expect(prompt.locator("[data-action=save]")).toBeVisible();
  await prompt.locator("[data-action=save]").click();
  await expect(prompt.locator("body")).toContainText("Saved");
  const items = (await sw.evaluate(async () => (self as any).__e2eItems())) as any[];
  expect(items.map((i) => i.title)).toContain(`newsite-test.com:${HTTPS_PORT}`);
});

test("changing a password shows the update prompt and updates", async ({ page, sw }) => {
  await page.goto(`${LEGIT}/change.html`);
  await page.fill("#current", "Correct-Password-1");
  await page.fill("#new", "Even-Better-Pass-77");
  await page.fill("#confirm", "Even-Better-Pass-77");
  await page.click("button[type=submit]");
  await expect(page.locator("#done")).toBeVisible();
  const prompt = await frameMatching(page, "/prompt.html");
  await expect(prompt.locator("body")).toContainText("Update password?");
  await prompt.locator("[data-action=update]").click();
  await expect(prompt.locator("body")).toContainText("Updated");
  const items = (await sw.evaluate(async () => (self as any).__e2eItems())) as any[];
  const id = items.find((i) => i.title === "Arevei Test").id;
  const detail = (await sw.evaluate(async (i) => (self as any).__e2eGetItem(i), id)) as any;
  expect(detail.item.data.password).toBe("Even-Better-Pass-77");
  expect(detail.item.password_history[0].value).toBe("Correct-Password-1");
});

test("SPA login (form disappears without navigation) shows the save prompt", async ({ page }) => {
  await page.goto(`https://spa-site.com:${HTTPS_PORT}/spa.html`);
  await page.fill("#username", "spa@user.com");
  await page.fill("#password", "Spa-Pass-123!");
  await page.click("#go");
  await expect(page.locator("#welcome")).toBeVisible();
  const prompt = await frameMatching(page, "/prompt.html");
  await expect(prompt.locator("[data-action=save]")).toBeVisible();
});
