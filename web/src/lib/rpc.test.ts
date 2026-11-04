import { describe, expect, it, vi } from "vitest";
import { createWorkerTransport, type WorkerLike } from "./rpc";

class FakeWorker implements WorkerLike {
  sent: any[] = [];
  terminated = false;
  private handlers: Record<string, ((ev: any) => void)[]> = {};
  postMessage(msg: unknown) {
    this.sent.push(msg);
  }
  addEventListener(type: string, fn: (ev: any) => void) {
    (this.handlers[type] ??= []).push(fn);
  }
  terminate() {
    this.terminated = true;
  }
  emit(type: string, data?: unknown) {
    this.handlers[type]?.forEach((h) => h({ data }));
  }
}

describe("worker RPC", () => {
  it("correlates out-of-order responses by id", async () => {
    const w = new FakeWorker();
    const t = createWorkerTransport(w);
    const a = t.call("a", { x: 1 });
    const b = t.call("b", {});
    expect(w.sent).toEqual([
      { id: 1, method: "a", args: { x: 1 } },
      { id: 2, method: "b", args: {} },
    ]);
    w.emit("message", { id: 2, ok: "B" });
    w.emit("message", { id: 1, ok: "A" });
    await expect(a).resolves.toBe("A");
    await expect(b).resolves.toBe("B");
    expect(t.pending()).toBe(0);
  });

  it("rejects with the engine error message", async () => {
    const w = new FakeWorker();
    const t = createWorkerTransport(w);
    const p = t.call("unlock", {});
    w.emit("message", { id: 1, error: "decryption failed" });
    await expect(p).rejects.toThrow("decryption failed");
  });

  it("ignores unknown ids and fails all pending calls on terminate (lock)", async () => {
    const w = new FakeWorker();
    const t = createWorkerTransport(w);
    const p = t.call("list_items", {});
    w.emit("message", { id: 999, ok: "stray" });
    t.terminate();
    expect(w.terminated).toBe(true);
    await expect(p).rejects.toThrow(/locked/);
    await expect(t.call("status", {})).rejects.toThrow(/locked/);
  });

  it("fails pending calls if the worker crashes", async () => {
    const w = new FakeWorker();
    const t = createWorkerTransport(w);
    const p = t.call("derive", {});
    w.emit("error");
    await expect(p).rejects.toThrow(/crashed/);
  });

  it("times out", async () => {
    vi.useFakeTimers();
    const w = new FakeWorker();
    const t = createWorkerTransport(w, 1000);
    const p = t.call("slow", {});
    vi.advanceTimersByTime(1001);
    await expect(p).rejects.toThrow(/timed out/);
    vi.useRealTimers();
  });
});
