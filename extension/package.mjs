// Zips the built extension for store upload:
//   dist/arevei-vault-chrome-<version>.zip    Edge Add-ons, Chrome Web Store, GitHub release
//   dist/arevei-vault-firefox-<version>.zip   addons.mozilla.org
// Run after build.mjs (`pnpm --filter extension package` does both). Refuses to package a test or
// development build. File order and timestamps are fixed, so the same build gives the same zip.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function walk(dir, prefix = "") {
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const full = join(dir, name);
      const rel = prefix ? `${prefix}/${name}` : name;
      return statSync(full).isDirectory() ? walk(full, rel) : [{ rel, full }];
    });
}

// Fixed DOS timestamp (1980-01-01 00:00) keeps the archive reproducible.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;

function zip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const { rel, full } of files) {
    const data = readFileSync(full);
    const name = Buffer.from(rel, "utf8");
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, packed);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4); // version made by
    entry.writeUInt16LE(20, 6); // version needed
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt16LE(DOS_TIME, 12);
    entry.writeUInt16LE(DOS_DATE, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(packed.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(name.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, name);

    offset += local.length + name.length + packed.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, centralBuf, end]);
}

let failed = false;
for (const target of ["chrome", "firefox"]) {
  const dir = join(dist, target);
  if (!existsSync(join(dir, "manifest.json"))) {
    console.error(`${target}: no build in dist/${target}. Run \`node build.mjs\` first.`);
    failed = true;
    continue;
  }
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  const sw = readFileSync(join(dir, "sw.js"), "utf8");
  const problems = [];
  if (/E2E/.test(manifest.name) || sw.includes("__e2e")) problems.push("this is an E2E test build");
  if (JSON.stringify(manifest).includes("localhost") || sw.includes("http://localhost:5173")) problems.push("this is a --dev build (allows localhost)");
  if (problems.length) {
    console.error(`${target}: refusing to package: ${problems.join("; ")}. Rebuild with \`node build.mjs\`.`);
    failed = true;
    continue;
  }
  const buf = zip(walk(dir));
  const name = `arevei-vault-${target}-${manifest.version}.zip`;
  writeFileSync(join(dist, name), buf);
  const sha = createHash("sha256").update(buf).digest("hex");
  console.log(`${name}  ${(buf.length / 1024).toFixed(0)} KB  sha256 ${sha}`);
}
if (failed) process.exit(1);
