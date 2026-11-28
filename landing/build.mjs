// Builds the static landing page into landing/dist.
//   node landing/build.mjs            build
//   node landing/build.mjs --serve    build, then serve dist on http://127.0.0.1:4173
// Env: APP_URL (default https://vault.arevei.com; "/" for same-origin links; the self-hosting
// request form posts to APP_URL/api/v1/contact/self-host), EDGE_EXTENSION_URL and EXTENSION_URL (the
// Edge Add-ons and Chrome Web Store listings; the "Add to Edge" / "Add to Chrome" buttons are left
// out while unset), EXTENSION_ZIP_URL (the extension zip for the manual-install guide; default: the
// latest GitHub release), ASSET_BASE (default "": relative
// assets; e.g. "/welcome/" when the page is served from a subfolder of the web app's origin),
// GTM_ID (a Google Tag Manager container id, e.g. GTM-XXXXXXX; adds the tag and loosens the CSP for
// it. Unset: no JavaScript at all. Refused when the page shares the vault's origin).

import { copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(here, "dist");

const APP_URL = (process.env.APP_URL || "https://vault.arevei.com").replace(/\/$/, "");
const EXTENSION_URL = (process.env.EXTENSION_URL || "").trim();
if (EXTENSION_URL && !/^https:\/\/[^\s"<>]+$/.test(EXTENSION_URL)) throw new Error("EXTENSION_URL must be an https:// URL");
const EDGE_EXTENSION_URL = (process.env.EDGE_EXTENSION_URL || "").trim();
const REPO_URL = "https://github.com/vinay-kumar-shakyawar/areveivault";
const EXTENSION_ZIP_URL = (process.env.EXTENSION_ZIP_URL || `${REPO_URL}/releases/latest/download/arevei-vault-extension.zip`).trim();
for (const [k, v] of Object.entries({ EDGE_EXTENSION_URL, EXTENSION_ZIP_URL })) {
  if (v && !/^https:\/\/[^\s"<>]+$/.test(v)) throw new Error(`${k} must be an https:// URL`);
}
const ASSET_BASE = process.env.ASSET_BASE || "";
const GTM_ID = (process.env.GTM_ID || "").trim();
if (GTM_ID && !/^GTM-[A-Z0-9]+$/.test(GTM_ID)) throw new Error("GTM_ID must look like GTM-XXXXXXX");
// A tag manager runs third-party code with the page's origin. Never let that be the vault's origin.
if (GTM_ID && (ASSET_BASE || !/^https?:\/\//.test(APP_URL))) {
  throw new Error("GTM_ID is only allowed when the landing page is on its own origin (no ASSET_BASE, absolute APP_URL)");
}
const gtmTags = GTM_ID
  ? `  <script src="gtm-init.js"></script>\n  <script async src="https://www.googletagmanager.com/gtm.js?id=${GTM_ID}"></script>\n`
  : "";

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "fonts"), { recursive: true });

// thanks.html and request-failed.html are where the API sends the visitor after the form post.
for (const page of ["index.html", "install-extension.html", "thanks.html", "request-failed.html"]) {
  const html = readFileSync(join(here, page), "utf8")
    // Browsers can't install an extension from a page; the button opens the store listing.
    .replace(/<!--ext-->([\s\S]*?)<!--\/ext-->/g, EXTENSION_URL ? "$1" : "")
    .replace(/<!--edge-->([\s\S]*?)<!--\/edge-->/g, EDGE_EXTENSION_URL ? "$1" : "")
    .replaceAll("{{EDGE_EXTENSION_URL}}", EDGE_EXTENSION_URL)
    .replaceAll("{{EXTENSION_ZIP_URL}}", EXTENSION_ZIP_URL)
    .replaceAll("{{RELEASES_URL}}", `${REPO_URL}/releases`)
    .replaceAll("{{APP_URL}}", APP_URL)
    .replaceAll("{{EXTENSION_URL}}", EXTENSION_URL)
    .replace(/href="(favicon\.svg|tokens\.css|styles\.css|install-extension\.html|fonts\/[^"]+)"/g, (_, f) => `href="${ASSET_BASE}${f}"`)
    .replace(/poster="(launch-film-poster\.jpg)"/g, (_, f) => `poster="${ASSET_BASE}${f}"`)
    .replace("</head>", () => `${gtmTags}</head>`);
  if (html.includes("{{")) throw new Error(`unreplaced placeholder in ${page}`);
  writeFileSync(join(out, page), html);
}
copyFileSync(join(here, "styles.css"), join(out, "styles.css"));
copyFileSync(join(here, "launch-film-poster.jpg"), join(out, "launch-film-poster.jpg"));
copyFileSync(join(root, "packages/ui/src/tokens.css"), join(out, "tokens.css"));
if (GTM_ID) copyFileSync(join(here, "gtm-init.js"), join(out, "gtm-init.js"));

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

// The page itself needs no JavaScript, so without GTM_ID it ships with the strictest policy. The
// only form posts to the vault API, which answers with a redirect back to this site. media-src
// allows the launch film; it is fetched only when the visitor presses play. With GTM_ID the policy
// also admits Google Tag Manager and Google Analytics, and nothing inline.
// Keep this policy in step with landing/vercel.json (GTM build) and the /welcome rule in
// web/vercel.json (no GTM).
const formAction = /^https?:\/\//.test(APP_URL) ? `'self' ${new URL(APP_URL).origin}` : "'self'";
const gtmCsp = GTM_ID
  ? ["script-src 'self' https://www.googletagmanager.com; connect-src https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; ", " https://*.google-analytics.com https://*.googletagmanager.com"]
  : ["", ""];
const csp =
  `default-src 'none'; ${gtmCsp[0]}style-src 'self'; font-src 'self'; img-src 'self' data:${gtmCsp[1]}; media-src https://res.cloudinary.com; base-uri 'none'; form-action ${formAction}; frame-ancestors 'none'; upgrade-insecure-requests`;
writeFileSync(
  join(out, "_headers"),
  `/*\n  Content-Security-Policy: ${csp}\n  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n`,
);

console.log(`built landing → ${out} (APP_URL=${APP_URL})`);

if (process.argv.includes("--serve")) {
  const types = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".jpg": "image/jpeg", ".woff2": "font/woff2" };
  createServer((req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^([/\\])+/, "");
    let file = join(out, path || "index.html");
    if (!file.startsWith(out) || !existsSync(file) || statSync(file).isDirectory()) file = join(out, "index.html");
    res.writeHead(200, { "Content-Type": types[extname(file)] || "application/octet-stream", "Content-Security-Policy": csp });
    createReadStream(file).pipe(res);
  }).listen(4173, "127.0.0.1", () => console.log("serving on http://127.0.0.1:4173"));
}
