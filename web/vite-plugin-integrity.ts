/**
 * Adds Subresource Integrity to every <script>/<link> emitted into index.html and
 * writes dist/bundle-hashes.json (sha256 of every output file) for publication
 * alongside reproducible builds (architecture §12.3).
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Plugin } from "vite";

const sri = (data: string | Uint8Array) => "sha384-" + createHash("sha384").update(data).digest("base64");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

export function integrity(): Plugin {
  let outDir = "dist";
  return {
    name: "arevei-integrity",
    apply: "build",
    enforce: "post",
    configResolved(c) {
      outDir = c.build.outDir;
    },
    generateBundle(_, bundle) {
      const html = bundle["index.html"];
      if (!html || html.type !== "asset") return;
      const tagRe = /<(script|link)\b([^>]*?)\s(src|href)="\/([^"]+)"([^>]*)>/g;
      html.source = String(html.source).replace(tagRe, (tag, el, pre, attr, file, post) => {
        const chunk = bundle[file];
        if (!chunk || /integrity=/.test(tag)) return tag;
        const data = chunk.type === "chunk" ? chunk.code : chunk.source;
        const cross = /crossorigin/.test(tag) ? "" : ' crossorigin="anonymous"';
        return `<${el}${pre} ${attr}="/${file}"${post} integrity="${sri(data)}"${cross}>`;
      });
    },
    closeBundle() {
      const files = walk(outDir)
        .filter((f) => !f.endsWith("bundle-hashes.json"))
        .sort();
      const hashes: Record<string, string> = {};
      for (const f of files) {
        hashes[relative(outDir, f).replace(/\\/g, "/")] = createHash("sha256").update(readFileSync(f)).digest("hex");
      }
      writeFileSync(
        join(outDir, "bundle-hashes.json"),
        JSON.stringify({ algorithm: "sha256", files: hashes }, null, 2) + "\n",
      );
    },
  };
}
