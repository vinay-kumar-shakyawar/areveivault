// Fixture web server for extension E2E tests. Serves the same pages on every
// hostname (Chromium maps all test hosts to 127.0.0.1 via --host-resolver-rules).
// HTTPS uses a throwaway self-signed certificate (test-only, never trust it elsewhere).
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
export const HTTPS_PORT = 4443;
export const HTTP_PORT = 4480;

const page = (title, body, script = "") => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px system-ui;margin:40px} input{display:block;margin:8px 0;width:260px;height:32px;padding:0 8px} button{height:36px}</style>
</head><body><h1>${title}</h1>${body}<script>${script}</script></body></html>`;

const pages = {
  "/login.html": page(
    "Sign in",
    `<form id="f" method="post" action="/done.html">
       <input id="username" name="username" type="email" autocomplete="username" placeholder="Email">
       <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Password">
       <button id="submit" type="submit">Sign in</button>
     </form>`,
  ),
  "/trap.html": page(
    "Sign in (with hidden trap fields)",
    `<form method="post" action="/done.html">
       <input id="username" name="username" type="email" autocomplete="username">
       <input id="password" name="password" type="password">
       <input id="trap-hidden" name="password_hidden" type="password" style="display:none">
       <div style="opacity:0"><input id="trap-transparent" name="password_shadow" type="password"></div>
       <input id="trap-offscreen" name="email2" type="email" style="position:absolute;left:-30000px">
       <button type="submit">Sign in</button>
     </form>`,
  ),
  "/frame-host.html": page(
    "Embeds a login form from another site",
    `<iframe id="frame" src="https://arevei-test.com:${HTTPS_PORT}/login.html" style="width:500px;height:400px;border:1px solid #ccc"></iframe>`,
  ),
  "/spa.html": page(
    "SPA login",
    `<div id="app"><input id="username" name="username" type="text" autocomplete="username">
       <input id="password" name="password" type="password">
       <button id="go" type="button">Log in</button></div>`,
    `document.getElementById('go').addEventListener('click', () => setTimeout(() => {
       document.getElementById('app').innerHTML = '<p id="welcome">Welcome back</p>';
     }, 50));`,
  ),
  "/change.html": page(
    "Change password",
    `<form method="post" action="/done.html">
       <input type="hidden" name="username" value="me@arevei-test.com" autocomplete="username">
       <input id="current" type="password" autocomplete="current-password">
       <input id="new" type="password" autocomplete="new-password">
       <input id="confirm" type="password" autocomplete="new-password">
       <button type="submit">Change password</button>
     </form>`,
  ),
  "/done.html": page("Done", `<p id="done">Signed in.</p>`),
};

function handler(req, res) {
  const path = new URL(req.url, "http://x").pathname;
  const body = pages[path];
  if (!body) {
    res.writeHead(404).end("not found");
    return;
  }
  // POSTs (form submissions) just render the page; request bodies are ignored.
  req.resume();
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(body);
}

export async function startServers() {
  const tls = { key: readFileSync(join(dir, "certs", "key.pem")), cert: readFileSync(join(dir, "certs", "cert.pem")) };
  const s1 = https.createServer(tls, handler);
  const s2 = http.createServer(handler);
  await Promise.all([new Promise((r) => s1.listen(HTTPS_PORT, "127.0.0.1", r)), new Promise((r) => s2.listen(HTTP_PORT, "127.0.0.1", r))]);
  return async () => {
    s1.close();
    s2.close();
  };
}
