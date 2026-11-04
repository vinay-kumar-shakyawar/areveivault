import { describe, expect, it } from "vitest";
import { decideFill, isOwnExtensionPage, resolveFrame, type MatchResult } from "../src/shared/policy";

const match = (over: Partial<MatchResult> = {}): MatchResult => ({
  matches: [{ id: "a", insecure: false }],
  lookalike: null,
  insecure_page: false,
  cross_origin_frame: false,
  ...over,
});

describe("resolveFrame", () => {
  it("top frame uses its own URL", () => {
    expect(resolveFrame({ url: "https://a.com/login", frameId: 0, topUrl: "https://a.com/login" })).toEqual({ url: "https://a.com/login" });
  });
  it("subframes carry the top URL for cross-origin checks", () => {
    expect(resolveFrame({ url: "https://b.com/f", frameId: 3, topUrl: "https://a.com/" })).toEqual({ url: "https://b.com/f", topUrl: "https://a.com/" });
  });
  it("about:blank frames are accepted only when same-origin with top", () => {
    expect(resolveFrame({ url: "about:blank", origin: "https://a.com", frameId: 2, topUrl: "https://a.com/x" })).toEqual({ url: "https://a.com/x" });
    expect(resolveFrame({ url: "about:blank", origin: "https://evil.com", frameId: 2, topUrl: "https://a.com/x" })).toBeNull();
    expect(resolveFrame({ url: "about:srcdoc", frameId: 2, topUrl: "https://a.com/x" })).toBeNull();
  });
  it("non-web pages are refused", () => {
    expect(resolveFrame({ url: "chrome://settings", frameId: 0 })).toBeNull();
    expect(resolveFrame({ url: "file:///c:/x.html", frameId: 0 })).toBeNull();
    expect(resolveFrame({ url: "https://b.com", frameId: 1 })).toBeNull();
  });
});

describe("decideFill", () => {
  it("fills a matching item on a secure page", () => {
    expect(decideFill(match(), "a", { visible: true, confirmInsecure: false })).toEqual({ ok: true });
  });
  it("refuses lookalikes even with a match", () => {
    expect(decideFill(match({ lookalike: { x: 1 } }), "a", { visible: true, confirmInsecure: true })).toEqual({ ok: false, reason: "lookalike" });
  });
  it("refuses items not matching this frame (e.g. cross-origin iframe filtered by engine)", () => {
    expect(decideFill(match({ matches: [], cross_origin_frame: true }), "a", { visible: true, confirmInsecure: true })).toEqual({
      ok: false,
      reason: "no-match",
    });
  });
  it("requires explicit confirmation on HTTP", () => {
    expect(decideFill(match({ insecure_page: true }), "a", { visible: true, confirmInsecure: false })).toEqual({ ok: false, reason: "needs-confirm" });
    expect(decideFill(match({ matches: [{ id: "a", insecure: true }] }), "a", { visible: true, confirmInsecure: true })).toEqual({ ok: true });
  });
  it("refuses when the menu is obscured (clickjacking)", () => {
    expect(decideFill(match(), "a", { visible: false, confirmInsecure: false })).toEqual({ ok: false, reason: "obscured" });
  });
});

describe("isOwnExtensionPage", () => {
  const id = "abcdefghijklmnop";
  it("accepts our own pages", () => {
    expect(isOwnExtensionPage({ id, url: `chrome-extension://${id}/menu.html#tok` }, id, "menu.html")).toBe(true);
    expect(isOwnExtensionPage({ id, url: `chrome-extension://${id}/popup.html` }, id)).toBe(true);
  });
  it("rejects other pages, other extensions and web pages", () => {
    expect(isOwnExtensionPage({ id, url: `chrome-extension://${id}/prompt.html` }, id, "menu.html")).toBe(false);
    expect(isOwnExtensionPage({ id: "other", url: `chrome-extension://other/menu.html` }, id, "menu.html")).toBe(false);
    expect(isOwnExtensionPage({ id, url: "https://evil.com/menu.html" }, id, "menu.html")).toBe(false);
    expect(isOwnExtensionPage({ id }, id)).toBe(false);
  });
});
