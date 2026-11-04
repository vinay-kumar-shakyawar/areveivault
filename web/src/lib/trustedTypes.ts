/**
 * The app's only Trusted Types policy (CSP: `require-trusted-types-for 'script';
 * trusted-types arevei-default`). Constructing a Worker is a TrustedScriptURL sink, so
 * this policy mints script URLs — and only for our own same-origin worker bundle.
 * It deliberately has no createHTML/createScript: HTML and script sinks stay blocked.
 */

interface TTPolicy {
  createScriptURL(url: string): unknown;
}
interface TTFactory {
  createPolicy(name: string, rules: { createScriptURL: (url: string) => string }): TTPolicy;
}

export const WORKER_PATH = /^\/(assets\/crypto\.worker-[\w-]+\.js|src\/crypto\.worker\.ts)$/;

export function allowWorkerUrl(url: string, origin: string): string {
  const u = new URL(url, origin);
  if (u.origin !== origin || !WORKER_PATH.test(u.pathname)) {
    throw new TypeError(`Blocked script URL: ${url}`);
  }
  return u.href;
}

let policy: TTPolicy | null | undefined;

/** Returns a TrustedScriptURL where Trusted Types exist, else the validated string. */
export function trustedWorkerUrl(url: string): string | URL {
  const tt = (globalThis as { trustedTypes?: TTFactory }).trustedTypes;
  if (!tt) return allowWorkerUrl(url, location.origin);
  if (policy === undefined) {
    policy = tt.createPolicy("arevei-default", { createScriptURL: (u) => allowWorkerUrl(u, location.origin) });
  }
  return policy!.createScriptURL(url) as string;
}
