import { describe, expect, it } from "vitest";
import { ClipboardManager, type ClipboardDeps } from "./clipboard";

function harness(focused = true) {
  let clock = 0;
  let timers: { fn: () => void; at: number; id: number }[] = [];
  let nextId = 1;
  const focusHandlers = new Set<() => void>();
  const writes: string[] = [];
  const env = { focused };
  const deps: ClipboardDeps = {
    write: async (t) => {
      if (!env.focused) throw new Error("Document is not focused");
      writes.push(t);
    },
    hasFocus: () => env.focused,
    onFocus: (fn) => {
      focusHandlers.add(fn);
      return () => focusHandlers.delete(fn);
    },
    setTimer: (fn, ms) => {
      const id = nextId++;
      timers.push({ fn, at: clock + ms, id });
      return id;
    },
    clearTimer: (id) => {
      timers = timers.filter((t) => t.id !== id);
    },
    now: () => clock,
  };
  const advance = async (ms: number) => {
    clock += ms;
    const due = timers.filter((t) => t.at <= clock);
    timers = timers.filter((t) => t.at > clock);
    for (const t of due) t.fn();
    await Promise.resolve();
    await Promise.resolve();
  };
  const focus = async () => {
    env.focused = true;
    focusHandlers.forEach((h) => h());
    await Promise.resolve();
    await Promise.resolve();
  };
  return { deps, writes, env, advance, focus, timers: () => timers };
}

describe("ClipboardManager", () => {
  it("clears after the configured seconds when focused", async () => {
    const h = harness();
    const c = new ClipboardManager(h.deps);
    await c.copy("s3cret", "Password", 30);
    expect(h.writes).toEqual(["s3cret"]);
    expect(c.getState()).toMatchObject({ label: "Password", expiresAt: 30_000 });
    await h.advance(29_999);
    expect(h.writes).toEqual(["s3cret"]);
    await h.advance(1);
    expect(h.writes).toEqual(["s3cret", ""]);
    expect(c.getState().label).toBeNull();
  });

  it("defers clearing until the page regains focus", async () => {
    const h = harness();
    const c = new ClipboardManager(h.deps);
    await c.copy("s3cret", "Password", 30);
    h.env.focused = false;
    await h.advance(30_000);
    expect(h.writes).toEqual(["s3cret"]);
    expect(c.getState().pendingClear).toBe(true);
    await h.focus();
    expect(h.writes).toEqual(["s3cret", ""]);
    expect(c.getState().pendingClear).toBe(false);
  });

  it("a new copy restarts the timer", async () => {
    const h = harness();
    const c = new ClipboardManager(h.deps);
    await c.copy("one", "A", 30);
    await h.advance(20_000);
    await c.copy("two", "B", 30);
    expect(h.timers()).toHaveLength(1);
    await h.advance(20_000);
    expect(h.writes).toEqual(["one", "two"]);
    await h.advance(10_000);
    expect(h.writes).toEqual(["one", "two", ""]);
  });

  it("0 seconds disables auto-clear", async () => {
    const h = harness();
    const c = new ClipboardManager(h.deps);
    await c.copy("x", "X", 0);
    expect(h.timers()).toHaveLength(0);
  });
});
