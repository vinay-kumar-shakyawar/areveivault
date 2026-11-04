/**
 * Opt-in Have I Been Pwned check using k-anonymity: only the first 5 hex chars of
 * SHA-1(password) leave the device, with response padding enabled. Requires the
 * documented CSP connect-src exception (csp.txt); otherwise fails closed.
 */

export async function sha1Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function parseRange(body: string, suffix: string): number {
  for (const line of body.split("\n")) {
    const [s, count] = line.trim().split(":");
    if (s === suffix) return parseInt(count, 10) || 0;
  }
  return 0;
}

/** Returns how many times each password appears in breaches (0 = not found). */
export async function checkPasswords(passwords: Map<string, string>, fetchFn: typeof fetch = fetch): Promise<Map<string, number>> {
  const byPrefix = new Map<string, { id: string; suffix: string }[]>();
  for (const [id, pw] of passwords) {
    if (!pw) continue;
    const h = await sha1Hex(pw);
    const list = byPrefix.get(h.slice(0, 5)) ?? [];
    list.push({ id, suffix: h.slice(5) });
    byPrefix.set(h.slice(0, 5), list);
  }
  const out = new Map<string, number>();
  for (const [prefix, entries] of byPrefix) {
    const res = await fetchFn(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) throw new Error(`breach check failed (${res.status})`);
    const body = await res.text();
    for (const e of entries) out.set(e.id, parseRange(body, e.suffix));
  }
  return out;
}
