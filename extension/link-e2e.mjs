// The specs live in /e2e/extension (outside this package). Link @playwright/test
// into that folder so Node's ESM resolver finds it from the spec files.
import { existsSync, mkdirSync, realpathSync, symlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const target = realpathSync(join(here, "node_modules", "@playwright", "test"));
const link = join(here, "..", "e2e", "extension", "node_modules", "@playwright", "test");
if (!existsSync(link)) {
  mkdirSync(dirname(link), { recursive: true });
  symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
}
