/**
 * Fill policy (architecture §13.3), as pure functions so they can be unit-tested.
 * Inputs come from the browser (`MessageSender`) and the engine's `match_url`.
 */

export interface SenderInfo {
  /** `sender.url` of the requesting frame. */
  url: string;
  /** `sender.origin` (Chrome 80+), may be undefined in some browsers. */
  origin?: string;
  frameId: number;
  /** `sender.tab.url` — the top-level page. */
  topUrl?: string;
}

export interface ResolvedFrame {
  /** URL to match credentials against. */
  url: string;
  /** Top page URL to pass as `top_url` for cross-origin-frame checks (undefined for the top frame). */
  topUrl?: string;
}

function originOf(u: string | undefined): string | null {
  if (!u) return null;
  try {
    const x = new URL(u);
    return x.origin === "null" ? null : x.origin;
  } catch {
    return null;
  }
}

/**
 * Determine the effective URL of a frame. `about:blank`/`srcdoc` frames inherit
 * their creator's origin; we accept them only when that origin equals the top
 * page's origin (then the top URL is used). Returns null when filling must be refused.
 */
export function resolveFrame(s: SenderInfo): ResolvedFrame | null {
  const isWeb = (u: string) => /^https?:\/\//i.test(u);
  if (s.frameId === 0) {
    const url = isWeb(s.url) ? s.url : s.topUrl && isWeb(s.topUrl) ? s.topUrl : null;
    return url ? { url } : null;
  }
  if (!s.topUrl || !isWeb(s.topUrl)) return null;
  if (isWeb(s.url)) return { url: s.url, topUrl: s.topUrl };
  // about:blank / about:srcdoc / blob: frames
  const o = s.origin ?? null;
  if (o && o === originOf(s.topUrl)) return { url: s.topUrl };
  return null;
}

export interface MatchSummary {
  id: string;
  insecure: boolean;
  title?: string;
  subtitle?: string;
  type?: string;
  has_totp?: boolean;
}

export interface MatchResult {
  matches: MatchSummary[];
  lookalike: unknown | null;
  insecure_page: boolean;
  cross_origin_frame: boolean;
}

export type FillDecision =
  | { ok: true }
  | { ok: false; reason: "lookalike" | "no-match" | "obscured" | "needs-confirm" | "locked" };

/**
 * Decide whether a user-selected item may be filled into the frame.
 * `match` must be computed by the engine for the browser-reported frame URL (+ top URL).
 */
export function decideFill(match: MatchResult, itemId: string, opts: { visible: boolean; confirmInsecure: boolean }): FillDecision {
  if (!opts.visible) return { ok: false, reason: "obscured" };
  if (match.lookalike) return { ok: false, reason: "lookalike" };
  const m = match.matches.find((x) => x.id === itemId);
  if (!m) return { ok: false, reason: "no-match" };
  if ((m.insecure || match.insecure_page) && !opts.confirmInsecure) return { ok: false, reason: "needs-confirm" };
  return { ok: true };
}

/** Returns true if a message from an extension page is really from our own extension page. */
export function isOwnExtensionPage(sender: { id?: string; url?: string }, extensionId: string, page?: string): boolean {
  if (sender.id !== extensionId || !sender.url) return false;
  const prefix = `chrome-extension://${extensionId}/`;
  const mozPrefix = /^moz-extension:\/\/[^/]+\//;
  if (!sender.url.startsWith(prefix) && !mozPrefix.test(sender.url)) return false;
  if (!page) return true;
  const path = sender.url.replace(/^[a-z-]+:\/\/[^/]+\//, "").split(/[?#]/)[0];
  return path === page;
}
