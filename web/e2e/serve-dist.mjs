// Static server for web/dist with the production headers from web/csp.txt.
// Proxies /api to API_TARGET if set; otherwise stubs /api/v1/auth/session -> 401.
import http from "node:http";
import https from "node:https";
import { readFileSync, existsSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const dist = process.argv[2];
const port = Number(process.argv[3] ?? 4173);
const apiTarget = process.env.API_TARGET;
const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types arevei-default";
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".woff2": "font/woff2", ".woff": "font/woff", ".svg": "image/svg+xml", ".json": "application/json" };
const sec = {
  "Content-Security-Policy": CSP,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

const handler = (req, res) => {
    if (req.url.startsWith("/api/")) {
      if (apiTarget) {
        const u = new URL(req.url, apiTarget);
        const p = http.request(u, { method: req.method, headers: { ...req.headers, host: u.host } }, (r) => {
          res.writeHead(r.statusCode, r.headers);
          r.pipe(res);
        });
        p.on("error", () => (res.writeHead(502), res.end()));
        req.pipe(p);
        return;
      }
      res.writeHead(401, { "Content-Type": "application/json", ...sec });
      return res.end(JSON.stringify({ error: "unauthorized", message: "no session" }));
    }
    let f = join(dist, decodeURIComponent(req.url.split("?")[0]));
    if (!existsSync(f) || statSync(f).isDirectory()) f = join(dist, "index.html");
    res.writeHead(200, { "Content-Type": types[extname(f)] ?? "application/octet-stream", ...sec });
    res.end(readFileSync(f));
  };
const srv = process.env.TLS ? https.createServer({ key: readFileSync(process.env.TLS_KEY ?? "key.pem"), cert: readFileSync(process.env.TLS_CERT ?? "cert.pem") }, handler) : http.createServer(handler);
srv.listen(port, () => console.log("serving on " + port));
