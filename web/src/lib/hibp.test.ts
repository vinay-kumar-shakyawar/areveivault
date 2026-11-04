import { describe, expect, it, vi } from "vitest";
import { checkPasswords, parseRange, sha1Hex } from "./hibp";

describe("HIBP k-anonymity", () => {
  it("hashes with SHA-1 uppercase hex", async () => {
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  });

  it("parses range responses including padding rows", () => {
    const body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n";
    expect(parseRange(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")).toBe(3861493);
    expect(parseRange(body, "FFFF")).toBe(0);
  });

  it("only sends the 5-char prefix, with padding requested", async () => {
    const fetchFn = vi.fn(async (_url: string, _init?: RequestInit) => new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"));
    const res = await checkPasswords(new Map([["item1", "password"]]), fetchFn as unknown as typeof fetch);
    expect(res.get("item1")).toBe(42);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("https://api.pwnedpasswords.com/range/5BAA6");
    expect(String(url)).not.toContain("1E4C9B");
    expect((init!.headers as Record<string, string>)["Add-Padding"]).toBe("true");
    expect(init!.credentials).toBe("omit");
  });
});
