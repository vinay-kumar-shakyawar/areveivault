// Builds the extension into dist/chrome and dist/firefox.
//   node build.mjs            release build (VAULT_ORIGIN, BUNDLE_MANIFEST_URL from env)
//   node build.mjs --e2e      test build: enables the E2E seeding hook (never ship this)
//   node build.mjs --dev      also allows http://localhost:5173 as the vault origin
import { build } from "esbuild";
import { copyFileSync, cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const root = dirname(fileURLToPath(import.meta.url));
const args = new Set(process.argv.slice(2));
const E2E = args.has("--e2e");
const DEV = args.has("--dev") || E2E;
const VAULT_ORIGIN = (process.env.VAULT_ORIGIN || "https://vault.arevei.com").replace(/\/$/, "");
const BUNDLE_MANIFEST_URL = process.env.BUNDLE_MANIFEST_URL || "";
const pkg = JSON.parse(await (await import("node:fs/promises")).readFile(join(root, "package.json"), "utf8"));
const out = join(root, "dist", "chrome");

rmSync(join(root, "dist"), { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const define = {
  __VAULT_ORIGIN__: JSON.stringify(VAULT_ORIGIN),
  __BUNDLE_MANIFEST_URL__: JSON.stringify(BUNDLE_MANIFEST_URL),
  __E2E__: JSON.stringify(E2E),
  __EXTRA_VAULT_ORIGINS__: JSON.stringify(DEV ? ["http://localhost:5173"] : []),
  "process.env.NODE_ENV": JSON.stringify(E2E ? "development" : "production"),
};

const common = { bundle: true, define, target: ["chrome116", "firefox121"], minify: !E2E, sourcemap: false, legalComments: "none", logLevel: "warning" };

await build({ ...common, entryPoints: { sw: "src/background/sw.ts" }, format: "esm", outdir: out });
await build({ ...common, entryPoints: { content: "src/content/content.ts" }, format: "iife", outdir: out });
await build({
  ...common,
  entryPoints: {
    popup: "src/ui/popup.tsx",
    menu: "src/ui/menu.ts",
    prompt: "src/ui/prompt.ts",
    onboarding: "src/ui/onboarding.tsx",
    offscreen: "src/ui/offscreen.ts",
  },
  format: "esm",
  jsx: "automatic",
  outdir: out,
});
await build({ ...common, entryPoints: { ui: "src/ui/ui.css" }, outdir: out });

for (const p of ["popup", "menu", "prompt", "onboarding", "offscreen"]) copyFileSync(join(root, "static", `${p}.html`), join(out, `${p}.html`));
copyFileSync(join(root, "..", "packages", "core-wasm", "pkg", "arevei_core_bg.wasm"), join(out, "arevei_core_bg.wasm"));

// ---- icons: silver shield on near-black, rendered to PNG without dependencies ----
function png(size) {
  const px = Buffer.alloc(size * size * 4);
  const shield = [
    [0.5, 0.12],
    [0.82, 0.24],
    [0.82, 0.5],
    [0.5, 0.9],
    [0.18, 0.5],
    [0.18, 0.24],
  ];
  const inPoly = (x, y) => {
    let c = false;
    for (let i = 0, j = shield.length - 1; i < shield.length; j = i++) {
      const [xi, yi] = shield[i];
      const [xj, yj] = shield[j];
      if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) c = !c;
    }
    return c;
  };
  const r = 0.22;
  for (let py = 0; py < size; py++)
    for (let pxl = 0; pxl < size; pxl++) {
      const x = (pxl + 0.5) / size;
      const y = (py + 0.5) / size;
      const dx = Math.max(r - x, 0, x - (1 - r));
      const dy = Math.max(r - y, 0, y - (1 - r));
      const inside = dx * dx + dy * dy <= r * r;
      const i = (py * size + pxl) * 4;
      if (!inside) continue;
      let [R, G, B] = [10, 10, 10];
      if (inPoly(x, y)) {
        const t = (x + y) / 2;
        const v = Math.round(232 - 64 * Math.sin(t * Math.PI));
        [R, G, B] = [v, v, v + 4];
        const hole = (x - 0.5) ** 2 + (y - 0.45) ** 2 < 0.007 || (Math.abs(x - 0.5) < 0.03 && y > 0.45 && y < 0.62);
        if (hole) [R, G, B] = [10, 10, 10];
      }
      px.set([R, G, B, 255], i);
    }
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) px.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}
const icons = {};
for (const s of [16, 32, 48, 128]) {
  writeFileSync(join(out, `icon-${s}.png`), png(s));
  icons[s] = `icon-${s}.png`;
}

// ---- manifest ----
const externalMatches = [`${VAULT_ORIGIN}/*`, ...(DEV ? ["http://localhost:5173/*"] : [])];
const manifest = {
  manifest_version: 3,
  name: E2E ? "Arevei Vault (E2E TEST BUILD)" : "Arevei Vault",
  version: pkg.version,
  description: "Zero-knowledge password manager for Arevei: save, autofill and generate passwords and one-time codes.",
  minimum_chrome_version: "116",
  icons,
  action: { default_popup: "popup.html", default_title: "Arevei Vault", default_icon: { 16: icons[16], 32: icons[32] } },
  background: { service_worker: "sw.js", type: "module" },
  content_scripts: [
    {
      matches: ["<all_urls>"],
      js: ["content.js"],
      all_frames: true,
      match_about_blank: true,
      match_origin_as_fallback: true,
      run_at: "document_idle",
    },
  ],
  permissions: ["storage", "scripting", "contextMenus", "offscreen", "alarms", "idle", "activeTab"],
  optional_permissions: ["privacy"],
  host_permissions: ["<all_urls>"],
  commands: {
    "fill-login": { suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" }, description: "Fill login for this site" },
  },
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
  web_accessible_resources: [{ resources: ["menu.html", "prompt.html"], matches: ["<all_urls>"], use_dynamic_url: true }],
  externally_connectable: { matches: externalMatches },
};
writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));

// ---- Firefox variant ----
const ff = join(root, "dist", "firefox");
cpSync(out, ff, { recursive: true });
const ffManifest = {
  ...manifest,
  background: { scripts: ["sw.js"], type: "module" },
  browser_specific_settings: { gecko: { id: "vault@arevei.com", strict_min_version: "121.0" } },
  // Firefox has no offscreen documents (clipboard falls back to the popup) and no externally_connectable.
  permissions: manifest.permissions.filter((p) => p !== "offscreen"),
  web_accessible_resources: [{ resources: ["menu.html", "prompt.html"], matches: ["<all_urls>"] }],
};
delete ffManifest.minimum_chrome_version;
delete ffManifest.externally_connectable;
delete ffManifest.content_scripts[0].match_origin_as_fallback;
writeFileSync(join(ff, "manifest.json"), JSON.stringify(ffManifest, null, 2));

console.log(`built ${E2E ? "E2E " : ""}extension → dist/chrome, dist/firefox (vault origin ${VAULT_ORIGIN})`);
