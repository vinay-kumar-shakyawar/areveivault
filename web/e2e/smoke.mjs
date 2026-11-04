// Browser smoke test of the built web app against a real server, under production CSP.
// Usage: serve dist over HTTPS with the csp.txt headers (see serve-dist.mjs, TLS=1 API_TARGET=...),
// then: node e2e/smoke.mjs https://localhost:4176 <outdir>   (needs playwright-core + a Chromium).
// The __Host- session cookie requires HTTPS, even on localhost.
import { chromium } from "playwright-core";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";

const BASE = process.argv[2] ?? "http://localhost:4175";
const OUT = process.argv[3] ?? ".";
const email = `owner${Date.now()}@arevei.com`;
const password = "Correct-Horse-Battery-Staple-91!";
const log = (...a) => console.log("•", ...a);

function totp(secretB32, t = Date.now() / 1000) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32.replace(/=+$/, "").toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(t / 30)));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}
const poll = async (fn, ms = 30000, what = "condition") => {
  const t = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - t > ms) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 250));
  }
};

const browser = await chromium.launch();
const problems = [];
async function newPage() {
  const ctx = await browser.newContext({ acceptDownloads: true, ignoreHTTPSErrors: true, permissions: ["clipboard-read", "clipboard-write"], viewport: { width: 1360, height: 860 } });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  page.on("console", (m) => m.type() === "error" && !/status of 40[19]|409/.test(m.text()) && problems.push(`console: ${m.text()}`));
  await page.addInitScript(() => document.addEventListener("securitypolicyviolation", (e) => console.error(`CSP VIOLATION ${e.violatedDirective} ${e.blockedURI}`)));
  return { ctx, page };
}

// ---------------- signup ----------------
const A = await newPage();
let p = A.page;
await p.goto(BASE + "/signup");
await p.getByTestId("signup-email").fill(email);
await p.getByTestId("signup-password").fill(password);
await p.getByTestId("signup-password-confirm").fill(password);
await poll(async () => Number(await p.getByTestId("strength").getAttribute("data-score")) >= 3, 30000, "strength");
await p.getByTestId("signup-submit").click();
await p.getByTestId("secret-key").waitFor({ timeout: 60000 });
const secretKey = (await p.getByTestId("secret-key").textContent()).trim();
log("secret key shown", secretKey.slice(0, 8) + "…");
const [dl] = await Promise.all([p.waitForEvent("download"), p.getByTestId("download-kit").click()]);
const kitPath = `${OUT}/kit.pdf`;
await dl.saveAs(kitPath);
const kitHead = (await import("node:fs")).readFileSync(kitPath).subarray(0, 5).toString();
log("emergency kit downloaded:", dl.suggestedFilename(), kitHead);
await p.getByTestId("kit-continue").click();
await p.getByTestId("secret-key-last4").fill(secretKey.replace(/-/g, "").slice(-4));
await p.getByTestId("confirm-last4").click();
const totpSecret = (await p.getByTestId("totp-secret").textContent()).trim();
await p.getByTestId("signup-totp").fill(totp(totpSecret));
await p.getByTestId("signup-totp-submit").click();
try { await p.getByTestId("nav-personal").waitFor({ timeout: 20000 }); } catch (e) { await p.screenshot({ path: OUT + "/fail.png" }); console.log(problems, await p.locator("[role=alert]").allTextContents(), JSON.stringify(await A.ctx.cookies())); throw e; }
log("signed up and vault open");

// ---------------- create a login ----------------
await p.getByTestId("new-item").click();
await p.getByTestId("edit-title").fill("Acme Hosting");
await p.getByTestId("edit-username").fill("ops@acme.com");
await p.getByTestId("generate-password").click();
await p.getByTestId("generator-use").click();
const generated = await p.getByTestId("edit-password").inputValue();
await p.getByTestId("edit-url-0").fill("https://panel.acme.com/login");
await p.getByTestId("edit-totp").fill("JBSWY3DPEHPK3PXP");
await p.getByTestId("edit-notes").fill("Ask **Dana** before rotating.\n\n- prod only\n- see [runbook](https://acme.com/runbook)");
await p.getByTestId("item-save").click();
await p.getByTestId("item-detail").waitFor();
await p.getByTestId("field-password-reveal").click();
await poll(async () => (await p.getByTestId("field-password-revealed").textContent()) === generated, 10000, "reveal");
log("item saved; revealed password matches generated (len", generated.length + ")");
await p.getByTestId("field-password-copy").click();
await p.getByTestId("clipboard-toast").waitFor();
const clip = await p.evaluate(() => navigator.clipboard.readText());
log("copy → clipboard matches:", clip === generated);
const code = await p.getByTestId("totp-code").getAttribute("data-code");
log("TOTP code rendered:", code === totp("JBSWY3DPEHPK3PXP") || code === totp("JBSWY3DPEHPK3PXP", Date.now() / 1000 - 1));
const richOk = (await p.getByTestId("rich-text").innerHTML()).includes("<strong>Dana</strong>");
log("rich text rendered:", richOk);
await p.screenshot({ path: `${OUT}/vault.png` });

// ---------------- command palette ----------------
await p.keyboard.press("Control+k");
await p.getByTestId("palette-input").fill("acme");
await p.getByTestId("palette-result").first().waitFor();
log("palette results:", await p.getByTestId("palette-result").count());
await p.keyboard.press("Escape");

// ---------------- lock / unlock ----------------
await p.getByTestId("lock-button").click();
await p.getByTestId("unlock-password").waitFor({ timeout: 20000 });
log("locked (worker terminated, page reloaded)");
await p.getByTestId("unlock-password").fill("wrong password here");
await p.getByTestId("unlock-submit").click();
await p.getByTestId("form-error").waitFor();
log("wrong password rejected:", (await p.getByTestId("form-error").textContent()).trim());
await p.getByTestId("unlock-password").fill(password);
await p.getByTestId("unlock-submit").click();
await p.getByTestId("item-row").first().waitFor({ timeout: 30000 });
log("unlocked; items:", await p.getByTestId("item-row").count());

// ---------------- second browser: login, same data ----------------
const B = await newPage();
const q = B.page;
await q.goto(BASE + "/");
await q.getByTestId("login-email").fill(email);
await q.getByTestId("login-password").fill(password);
await q.getByTestId("login-secret-key").fill(secretKey);
await q.getByTestId("login-submit").click();
await q.getByTestId("login-totp").waitFor({ timeout: 60000 });
// The signup step used the current code; servers reject replay, so wait for the next step.
const step = Math.floor(Date.now() / 30000);
await poll(async () => Math.floor(Date.now() / 30000) > step, 35000, "next TOTP step");
await q.getByTestId("login-totp").fill(totp(totpSecret));
await q.getByTestId("login-submit").click();
await q.locator('[data-item-title="Acme Hosting"]').waitFor({ timeout: 30000 });
log("second browser sees the item");

// ---------------- import 500 Chrome rows ----------------
let csv = "name,url,username,password,note\n";
for (let i = 0; i < 500; i++) csv += `site${i}.example.org,https://site${i}.example.org/login,user${i},Pw-${i}-x9!Q,\n`;
writeFileSync(`${OUT}/chrome.csv`, csv);
await p.getByTestId("nav-tools").click();
await p.getByTestId("import-file").setInputFiles(`${OUT}/chrome.csv`);
await p.getByTestId("import-preview").click();
await p.getByTestId("import-count").waitFor();
log("import preview:", (await p.getByTestId("import-count").textContent()).trim());
const t0 = Date.now();
await p.getByTestId("import-run").click();
await poll(async () => (await p.getByTestId("import-run").count()) === 0 && (await p.getByTestId("import-count").count()) === 0, 180000, "import");
log(`imported 500 in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
await p.getByTestId("nav-personal").click();
await poll(async () => (await p.getByTestId("item-row").count()) >= 501, 30000, "501 rows");
log("personal vault rows:", await p.getByTestId("item-row").count());

// ---------------- admin: client + project + project item ----------------
await p.getByTestId("nav-admin-projects").click();
await p.getByTestId("client-name").fill("Acme Corp");
await p.getByTestId("client-create").click();
await p.getByTestId("project-add-Acme Corp").click();
await p.getByTestId("project-name").fill("Website Redesign");
await p.getByTestId("project-create").click();
await p.getByTestId("nav-project-Website Redesign").waitFor({ timeout: 20000 });
await p.getByTestId("nav-project-Website Redesign").click();
await p.getByTestId("new-item").click();
await p.getByTestId("type-api_key").click();
await p.getByTestId("edit-title").fill("Stripe prod");
await p.getByTestId("edit-key").fill("sk_live_canary_123");
await p.getByTestId("item-save").click();
await p.getByTestId("item-detail").waitFor();
log("project item created:", await p.getByTestId("view-title").textContent());
await q.getByTestId("nav-all").click();
await p.getByTestId("nav-security").click();
await p.getByTestId("security-weak-passwords").waitFor();
log("security dashboard rendered");
await p.screenshot({ path: `${OUT}/security.png` });

// ---------------- Phase 3: invite → approve → share → revoke+rotate ----------------
await p.getByTestId("nav-admin-invites").click();
const memberEmail = `member${Date.now()}@arevei.com`;
await p.getByTestId("invite-email").fill(memberEmail);
await p.getByTestId("invite-create").click();
const inviteLink = (await p.getByTestId("invite-link").textContent()).trim();
log("invite link created");

const C = await newPage();
const m = C.page;
await m.goto(inviteLink);
await m.getByTestId("signup-email").fill(memberEmail);
await m.getByTestId("signup-password").fill(password + "m");
await m.getByTestId("signup-password-confirm").fill(password + "m");
await poll(async () => Number(await m.getByTestId("strength").getAttribute("data-score")) >= 3, 30000, "strength");
await m.getByTestId("signup-submit").click();
await m.getByTestId("secret-key").waitFor({ timeout: 60000 });
const mSecret = (await m.getByTestId("secret-key").textContent()).trim();
await Promise.all([m.waitForEvent("download"), m.getByTestId("download-kit").click()]);
await m.getByTestId("kit-continue").click();
await m.getByTestId("secret-key-last4").fill(mSecret.replace(/-/g, "").slice(-4));
await m.getByTestId("confirm-last4").click();
const mTotp = (await m.getByTestId("totp-secret").textContent()).trim();
await m.getByTestId("signup-totp").fill(totp(mTotp));
await m.getByTestId("signup-totp-submit").click();
await m.getByTestId("my-fingerprint").waitFor({ timeout: 30000 });
await poll(async () => !(await m.getByTestId("my-fingerprint").textContent()).includes("…"), 10000, "fingerprint");
const memberFp = (await m.getByTestId("my-fingerprint").textContent()).trim();
log("member pending; fingerprint", memberFp.slice(0, 9) + "…");

await p.getByTestId("nav-admin-members").click();
await p.getByTestId(`approve-${memberEmail}`).click();
await poll(async () => ((await p.getByTestId("approve-fingerprint").textContent()) ?? "").trim().length > 10, 10000, "admin fingerprint");
const adminSees = (await p.getByTestId("approve-fingerprint").textContent()).trim();
log("fingerprints match out-of-band:", adminSees === memberFp);
await p.getByTestId("approve-checkbox").check();
await p.getByTestId("approve-confirm").click();
await p.getByTestId("approve-modal").waitFor({ state: "hidden", timeout: 20000 });
log("member approved");

await p.getByTestId("nav-admin-projects").click();
await p.getByTestId("project-members-Website Redesign").click();
await p.getByTestId("access-user").selectOption({ label: memberEmail });
await p.getByTestId("access-role").selectOption("read_only");
await p.getByTestId("access-add").click();
await p.getByText(memberEmail, { exact: false }).first().waitFor();
log("project shared read-only with member");

// The member's page may already have left the pending screen via an SSE-triggered sync.
if (await m.getByRole("button", { name: "Check again" }).count()) await m.getByRole("button", { name: "Check again" }).click();
else if (await m.getByTestId("sync-now").count()) await m.getByTestId("sync-now").click();
await m.getByTestId("nav-project-Website Redesign").waitFor({ timeout: 30000 });
log("member left pending state automatically / via refresh");
await m.getByTestId("nav-project-Website Redesign").click();
await m.locator('[data-item-title="Stripe prod"]').click();
await m.getByTestId("field-key-reveal").click();
await poll(async () => ((await m.getByTestId("field-key-revealed").textContent()) ?? "") === "sk_live_canary_123", 10000, "member reveal");
log("member decrypted shared item; read-only hides edit:", (await m.getByTestId("item-edit").count()) === 0);

// Revoke: admin removes the member -> rotation; member loses the project.
await p.getByRole("button", { name: `Remove ${memberEmail}` }).click();
await poll(async () => (await p.getByRole("button", { name: `Remove ${memberEmail}` }).count()) === 0, 30000, "removal");
log("access removed + project key rotated");
await m.getByTestId("sync-now").click();
await poll(async () => (await m.getByTestId("nav-project-Website Redesign").count()) === 0, 30000, "member loses project");
log("member no longer sees the project");

await p.goto(BASE + "/");
await p.getByTestId("unlock-password").fill(password);
await p.getByTestId("unlock-submit").click();
await p.getByTestId("nav-admin-projects").click();
await p.getByText("key v2").first().waitFor({ timeout: 20000 });
log("admin still reads project after rotation (key v2)");

await browser.close();
const csp = problems.filter((x) => /CSP VIOLATION/.test(x));
console.log(JSON.stringify({ problems, cspViolations: csp.length }, null, 2));
if (problems.length) process.exit(1);
