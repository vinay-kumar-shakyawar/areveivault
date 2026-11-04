import { describe, expect, it } from "vitest";
import { allowWorkerUrl } from "./trustedTypes";

const O = "https://vault.arevei.com";

describe("Trusted Types worker policy", () => {
  it("allows only our same-origin crypto worker bundle", () => {
    expect(allowWorkerUrl("/assets/crypto.worker-C_TmbF48.js", O)).toBe(`${O}/assets/crypto.worker-C_TmbF48.js`);
    expect(allowWorkerUrl("/src/crypto.worker.ts", O)).toBe(`${O}/src/crypto.worker.ts`);
  });

  it("rejects other scripts, origins, and schemes", () => {
    for (const bad of [
      "/assets/index-abc.js",
      "/assets/crypto.worker-x.js/../evil.js",
      "https://evil.com/assets/crypto.worker-a.js",
      "data:text/javascript,alert(1)",
      "blob:https://vault.arevei.com/123",
      "javascript:alert(1)",
    ]) {
      expect(() => allowWorkerUrl(bad, O), bad).toThrow();
    }
  });
});
