/// <reference lib="webworker" />
/**
 * Dedicated crypto Worker: hosts the Rust engine (core.wasm). All keys live in
 * WASM linear memory here; the UI thread only receives what it must render.
 * Terminating this worker (lock) discards every key at once.
 */
import init, { call } from "@arevei/core-wasm";
import wasmUrl from "@arevei/core-wasm/wasm?url";
import type { RpcRequest, RpcResponse } from "./lib/rpc";

declare const self: DedicatedWorkerGlobalScope;

const ready = init({ module_or_path: wasmUrl });

// Strictly serialize engine calls (the engine is single-threaded, stateful).
let queue: Promise<unknown> = Promise.resolve();

self.addEventListener("message", (ev: MessageEvent<RpcRequest>) => {
  const { id, method, args } = ev.data ?? ({} as RpcRequest);
  if (typeof id !== "number" || typeof method !== "string") return;
  queue = queue.then(async () => {
    let res: RpcResponse;
    try {
      await ready;
      const raw = JSON.parse(call(method, JSON.stringify(args ?? {}))) as { ok?: unknown; error?: string };
      res = raw.error !== undefined ? { id, error: raw.error } : { id, ok: raw.ok };
    } catch (e) {
      res = { id, error: e instanceof Error ? e.message : "engine failure" };
    }
    self.postMessage(res);
  });
});
