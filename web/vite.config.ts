/// <reference types="vitest" />
import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { integrity } from "./vite-plugin-integrity";

// The session cookie is `__Host-…; Secure`, which browsers won't store over plain
// http://localhost, so sign-in needs HTTPS in dev too. Point these at a local cert
// (e.g. from mkcert) and set the server's PUBLIC_ORIGIN=https://localhost:5173.
const tls =
  process.env.DEV_TLS_CERT && process.env.DEV_TLS_KEY
    ? { cert: readFileSync(process.env.DEV_TLS_CERT), key: readFileSync(process.env.DEV_TLS_KEY) }
    : undefined;

export default defineConfig({
  plugins: [react(), integrity()],
  worker: { format: "es" },
  build: {
    target: "es2022",
    sourcemap: false,
    // The preload polyfill would be inlined into index.html, which our CSP forbids.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    chunkSizeWarningLimit: 2000,
  },
  server: {
    port: 5173,
    https: tls,
    proxy: { "/api": { target: "http://127.0.0.1:8080", changeOrigin: false } },
  },
  test: { environment: "jsdom", include: ["src/**/*.test.{ts,tsx}"] },
});
