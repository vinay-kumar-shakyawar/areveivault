/**
 * Request/response RPC over a Worker. Protocol: `{id, method, args}` → `{id, ok}` | `{id, error}`.
 * The UI thread never imports the wasm; it only holds this transport.
 */
import { EngineError, type EngineTransport } from "@arevei/client";

export interface WorkerLike {
  postMessage(msg: unknown): void;
  addEventListener(type: "message", fn: (ev: MessageEvent) => void): void;
  addEventListener(type: "error", fn: (ev: Event) => void): void;
  terminate(): void;
}

export interface RpcRequest {
  id: number;
  method: string;
  args: unknown;
}

export type RpcResponse = { id: number; ok: unknown } | { id: number; error: string };

export interface WorkerTransport {
  call: EngineTransport;
  terminate(): void;
  pending(): number;
}

export function createWorkerTransport(worker: WorkerLike, timeoutMs = 60_000): WorkerTransport {
  let next = 1;
  let dead = false;
  const waiting = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();

  const failAll = (msg: string) => {
    for (const [id, w] of waiting) {
      clearTimeout(w.timer);
      w.reject(new EngineError(msg));
      waiting.delete(id);
    }
  };

  worker.addEventListener("message", (ev: MessageEvent) => {
    const res = ev.data as RpcResponse;
    const w = waiting.get(res?.id);
    if (!w) return;
    waiting.delete(res.id);
    clearTimeout(w.timer);
    if ("error" in res) w.reject(new EngineError(res.error));
    else w.resolve(res.ok);
  });
  worker.addEventListener("error", () => failAll("crypto worker crashed"));

  return {
    call(method, args) {
      if (dead) return Promise.reject(new EngineError("vault is locked"));
      const id = next++;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting.delete(id);
          reject(new EngineError(`engine call ${method} timed out`));
        }, timeoutMs);
        waiting.set(id, { resolve, reject, timer });
        worker.postMessage({ id, method, args: args ?? {} } satisfies RpcRequest);
      });
    },
    terminate() {
      dead = true;
      worker.terminate();
      failAll("vault is locked");
    },
    pending: () => waiting.size,
  };
}
