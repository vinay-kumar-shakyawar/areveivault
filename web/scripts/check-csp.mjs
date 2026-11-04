#!/usr/bin/env node
// Fails if dist/ contains anything the CSP in csp.txt would block, or anything
// that loads from another origin. Run after `vite build`.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
if (!existsSync(dist)) {
  console.error("dist/ not found; run vite build first");
  process.exit(1);
}
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));

// Origins that may appear in code: XML namespaces, React error-doc links (strings
// only), and the opt-in HIBP range API (documented connect-src exception).
const allowedFetchOrigins = ["https://api.pwnedpasswords.com"];
const problems = [];
const files = walk(dist);

for (const file of files) {
  const ext = extname(file);
  if (ext === ".html") {
    const html = readFileSync(file, "utf8");
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      if (!/\bsrc=/.test(m[1]) || m[2].trim()) problems.push(`${file}: inline <script>`);
      else if (!/integrity=/.test(m[1])) problems.push(`${file}: <script> without integrity`);
    }
    if (/<style\b/i.test(html)) problems.push(`${file}: inline <style>`);
    if (/\sstyle\s*=/i.test(html)) problems.push(`${file}: style= attribute`);
    if (/\son[a-z]+\s*=/i.test(html)) problems.push(`${file}: inline event handler`);
    for (const m of html.matchAll(/<link\b[^>]*rel="(?:stylesheet|modulepreload)"[^>]*>/gi)) {
      if (!/integrity=/.test(m[0])) problems.push(`${file}: <link> without integrity`);
    }
    for (const m of html.matchAll(/\b(?:src|href)\s*=\s*"((?:https?:)?\/\/[^"]+)"/gi)) {
      problems.push(`${file}: external resource ${m[1]}`);
    }
  }
  if (ext === ".js") {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/\bfetch\(\s*["'`](https?:\/\/[^"'`/]+)/g)) {
      if (!allowedFetchOrigins.includes(m[1])) problems.push(`${file}: network call to ${m[1]}`);
    }
    for (const m of text.matchAll(/\bimport\(\s*["'`](https?:\/\/[^"'`]+)/g)) problems.push(`${file}: remote import ${m[1]}`);
    // (React DOM ships dormant innerHTML sinks reachable only via dangerouslySetInnerHTML or
    // rendering <script>; the source scan below forbids both and Trusted Types blocks them.)
    if (/new Function\(|\beval\(/.test(text)) problems.push(`${file}: eval/new Function`);
  }
  if (ext === ".css") {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/url\(\s*["']?((?:https?:)?\/\/[^"')]+)/g)) problems.push(`${file}: external CSS url ${m[1]}`);
    if (/@import/.test(text)) problems.push(`${file}: @import in CSS`);
  }
}

// Source scan: our code must never touch HTML sinks (Trusted Types: require-trusted-types-for 'script').
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcDirs = [join(root, "src"), join(root, "..", "packages", "ui", "src"), join(root, "..", "packages", "client", "src")];
const sinks = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(|createContextualFragment/;
for (const dir of srcDirs.filter(existsSync)) {
  for (const file of walk(dir).filter((f) => /\.(tsx?|jsx?)$/.test(f) && !/\.test\./.test(f))) {
    const text = readFileSync(file, "utf8");
    if (sinks.test(text)) problems.push(`${file}: HTML sink in source`);
  }
}

if (problems.length) {
  console.error("CSP check FAILED:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`CSP check passed (${files.length} files scanned)`);
