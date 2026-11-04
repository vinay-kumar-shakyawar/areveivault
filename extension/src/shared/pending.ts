/**
 * Captured credentials awaiting a save/update decision. Held only in service-worker
 * memory, keyed by tab, and expired after a TTL (architecture §13.4).
 */

export interface PendingCapture {
  token: string;
  tabId: number;
  url: string;
  username: string;
  password: string;
  kind: "save" | "update";
  /** For updates: the existing item. */
  itemId?: string;
  itemTitle?: string;
  createdAt: number;
  shown: boolean;
}

export class PendingStore {
  private byTab = new Map<number, PendingCapture>();

  constructor(
    private ttlMs: number,
    private now: () => number = Date.now,
  ) {}

  put(p: Omit<PendingCapture, "createdAt" | "shown">): PendingCapture {
    const full: PendingCapture = { ...p, createdAt: this.now(), shown: false };
    this.byTab.set(p.tabId, full);
    return full;
  }

  private alive(p: PendingCapture | undefined): PendingCapture | undefined {
    if (!p) return undefined;
    if (this.now() - p.createdAt > this.ttlMs) {
      this.byTab.delete(p.tabId);
      wipe(p);
      return undefined;
    }
    return p;
  }

  forTab(tabId: number): PendingCapture | undefined {
    return this.alive(this.byTab.get(tabId));
  }

  byToken(token: string): PendingCapture | undefined {
    for (const p of this.byTab.values()) if (p.token === token) return this.alive(p);
    return undefined;
  }

  /** Same credentials captured twice (submit + navigation heuristics) are deduplicated. */
  isDuplicate(tabId: number, username: string, password: string): boolean {
    const p = this.forTab(tabId);
    return !!p && p.username === username && p.password === password;
  }

  remove(token: string): void {
    for (const [tab, p] of this.byTab) {
      if (p.token === token) {
        this.byTab.delete(tab);
        wipe(p);
      }
    }
  }

  clearTab(tabId: number): void {
    const p = this.byTab.get(tabId);
    if (p) wipe(p);
    this.byTab.delete(tabId);
  }

  clear(): void {
    for (const p of this.byTab.values()) wipe(p);
    this.byTab.clear();
  }

  sweep(): void {
    for (const p of [...this.byTab.values()]) this.alive(p);
  }

  get size(): number {
    return this.byTab.size;
  }

  /** Snapshot for chrome.storage.session (memory-only), so a service-worker restart keeps captures. */
  toJSON(): PendingCapture[] {
    this.sweep();
    return [...this.byTab.values()];
  }

  load(list: PendingCapture[]): void {
    for (const p of list) if (!this.byTab.has(p.tabId)) this.byTab.set(p.tabId, { ...p });
    this.sweep();
  }
}

/** Best-effort: drop references to the secret (JS strings can't be zeroized). */
function wipe(p: PendingCapture) {
  p.password = "";
  p.username = "";
}
