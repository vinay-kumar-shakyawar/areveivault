/**
 * CSP-compatibility rules enforced at the source level (the built output is checked
 * by scripts/check-csp.mjs). See csp.txt for the policy.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..");
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const sources = [...walk(join(root, "src")), ...walk(join(root, "..", "packages", "ui", "src"))].filter(
  (f) => /\.(tsx?|css)$/.test(f) && !/\.test\./.test(f),
);

describe("CSP compatibility", () => {
  it("index.html has no inline script, style, or event handlers", () => {
    const html = readFileSync(join(root, "index.html"), "utf8");
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      expect(m[1]).toMatch(/src=/);
      expect(m[2].trim()).toBe("");
    }
    expect(html).not.toMatch(/<style|\sstyle=|\son[a-z]+=/i);
  });

  it("source never uses HTML sinks (Trusted Types)", () => {
    const sinks = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/;
    const bad = sources.filter((f) => sinks.test(readFileSync(f, "utf8")));
    expect(bad).toEqual([]);
  });

  it("no eval, string timers, or runtime <style> injection", () => {
    const patterns = /\beval\(|new Function\(|setTimeout\(\s*["'`]|createElement\(\s*["']style["']\)/;
    const bad = sources.filter((f) => patterns.test(readFileSync(f, "utf8")));
    expect(bad).toEqual([]);
  });

  it("no third-party origins in source (fonts are self-hosted)", () => {
    const allowed = ["https://api.pwnedpasswords.com", "http://www.w3.org", "https://example.com", "https://…"];
    const bad: string[] = [];
    for (const f of sources) {
      for (const m of readFileSync(f, "utf8").matchAll(/https?:\/\/[a-z0-9.-]+/gi)) {
        if (!allowed.some((a) => m[0].startsWith(a)) && !/acme\.com|example/.test(m[0])) bad.push(`${f}: ${m[0]}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("nothing decrypted is written to Web Storage", () => {
    // Only non-secret settings and a lock message may use local/sessionStorage.
    const uses = sources.flatMap((f) =>
      [...readFileSync(f, "utf8").matchAll(/(localStorage|sessionStorage)\.setItem\(\s*([^,]+),/g)].map((m) => m[2].trim()),
    );
    for (const key of uses) expect(['KEY', '"arevei-lock-message"']).toContain(key);
  });
});
