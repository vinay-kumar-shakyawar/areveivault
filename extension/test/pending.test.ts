import { describe, expect, it } from "vitest";
import { PendingStore } from "../src/shared/pending";

describe("PendingStore", () => {
  it("expires captures after the TTL and wipes them", () => {
    let now = 1000;
    const s = new PendingStore(5000, () => now);
    const p = s.put({ token: "t1", tabId: 1, url: "https://a.com", username: "u", password: "pw", kind: "save" });
    expect(s.forTab(1)?.token).toBe("t1");
    expect(s.byToken("t1")).toBeDefined();
    now += 5001;
    expect(s.forTab(1)).toBeUndefined();
    expect(p.password).toBe("");
    expect(s.size).toBe(0);
  });
  it("keeps one capture per tab and deduplicates identical credentials", () => {
    const s = new PendingStore(60_000);
    s.put({ token: "a", tabId: 1, url: "https://a.com", username: "u", password: "p1", kind: "save" });
    expect(s.isDuplicate(1, "u", "p1")).toBe(true);
    expect(s.isDuplicate(1, "u", "p2")).toBe(false);
    s.put({ token: "b", tabId: 1, url: "https://a.com", username: "u", password: "p2", kind: "save" });
    expect(s.byToken("a")).toBeUndefined();
    expect(s.size).toBe(1);
  });
  it("remove / clearTab / clear", () => {
    const s = new PendingStore(60_000);
    s.put({ token: "a", tabId: 1, url: "u", username: "", password: "x", kind: "save" });
    s.put({ token: "b", tabId: 2, url: "u", username: "", password: "y", kind: "update" });
    s.remove("a");
    expect(s.forTab(1)).toBeUndefined();
    s.clearTab(2);
    expect(s.size).toBe(0);
    s.put({ token: "c", tabId: 3, url: "u", username: "", password: "z", kind: "save" });
    s.clear();
    expect(s.size).toBe(0);
  });
});
