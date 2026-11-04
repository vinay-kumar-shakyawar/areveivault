/** Loads the Rust engine (WASM) into the service worker. */

import { initSync, call } from "@arevei/core-wasm";
import { createEngine, directTransport, type Engine } from "@arevei/client";

let ready: Promise<Engine> | null = null;

export function getEngine(): Promise<Engine> {
  if (!ready) {
    ready = (async () => {
      const res = await fetch(chrome.runtime.getURL("arevei_core_bg.wasm"));
      initSync({ module: await res.arrayBuffer() });
      return createEngine(directTransport(call));
    })();
    ready.catch(() => (ready = null));
  }
  return ready;
}
