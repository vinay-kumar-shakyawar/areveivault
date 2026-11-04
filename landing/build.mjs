// Builds the static landing page into landing/dist.
//   node landing/build.mjs            build
//   node landing/build.mjs --serve    build, then serve dist on http://127.0.0.1:4173
// Env: APP_URL (default https://vault.arevei.com), SELF_HOST_GUIDE_URL (default #self-host).

import { copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(here, "dist");

const APP_URL = (process.env.APP_URL || "https://vault.arevei.com").replace(/\/$/, "");
const SELF_HOST_GUIDE_URL = process.env.SELF_HOST_GUIDE_URL || "#self-host";

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "fonts"), { recursive: true });

const html = readFileSync(join(here, "index.html"), "utf8")
  .replaceAll("{{APP_URL}}", APP_URL)
  .replaceAll("{{SELF_HOST_GUIDE_URL}}", SELF_HOST_GUIDE_URL);
if (html.includes("{{")) throw new Error("unreplaced placeholder in index.html");
writeFileSync(join(out, "index.html"), html);
copyFileSync(join(here, "styles.css"), join(out, "styles.css"));
copyFileSync(join(root, "packages/ui/src/tokens.css"), join(out, "tokens.css"));

// Self-hosted fonts from the web app's @fontsource packages (no Google Fonts / CDNs).
const fontDirs = [
  join(root, "web/node_modules/@fontsource/inter/files"),
  join(root, "web/node_modules/@fontsource/jetbrains-mono/files"),
];
const fonts = [
  "inter-latin-400-normal.woff2",
  "inter-latin-500-normal.woff2",
  "inter-latin-600-normal.woff2",
  "inter-latin-700-normal.woff2",
  "jetbrains-mono-latin-400-normal.woff2",
  "jetbrains-mono-latin-500-normal.woff2",
];
for (const f of fonts) {
  const src = fontDirs.map((d) => join(d, f)).find(existsSync);
  if (!src) throw new Error(`font ${f} not found; run pnpm install first`);
  copyFileSync(src, join(out, "fonts", f));
}

writeFileSync(
  join(out, "favicon.svg"),
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#e8e8e8"/><stop offset=".5" stop-color="#a8a9ad"/><stop offset="1" stop-color="#d4d4d4"/></linearGradient></defs><rect width="32" height="32" rx="7" fill="#0a0a0a"/><path d="M16 4.5l9.5 3.6v7.2c0 5.9-4 10.2-9.5 12.3-5.5-2.1-9.5-6.4-9.5-12.3V8.1z" fill="none" stroke="url(#g)" stroke-width="1.8" stroke-linejoin="round"/><circle cx="16" cy="14" r="2.6" fill="url(#g)"/><path d="M14.8 15.8h2.4l.8 5h-4z" fill="url(#g)"/></svg>`,
);

// The page needs no JavaScript at all, so it can ship with the strictest policy.
const csp =
  "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests";
writeFileSync(
  join(out, "_headers"),
  `/*\n  Content-Security-Policy: ${csp}\n  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n`,
);

console.log(`built landing → ${out} (APP_URL=${APP_URL})`);

if (process.argv.includes("--serve")) {
  const types = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".svg": "image/svg+xml", ".woff2": "font/woff2" };
  createServer((req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^([/\\])+/, "");
    let file = join(out, path || "index.html");
    if (!file.startsWith(out) || !existsSync(file) || statSync(file).isDirectory()) file = join(out, "index.html");
    res.writeHead(200, { "Content-Type": types[extname(file)] || "application/octet-stream", "Content-Security-Policy": csp });
    createReadStream(file).pipe(res);
  }).listen(4173, "127.0.0.1", () => console.log("serving on http://127.0.0.1:4173"));
}
