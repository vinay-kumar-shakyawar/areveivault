/**
 * Pull-based sync (docs/api.md "Sync"). Ciphertext rows go straight into the
 * engine; the org signing key is pinned on first sight (TOFU) by the caller's store.
 */

import { Api } from "./api";
import { Engine } from "./engine";

export interface PinStore {
  get(orgId: string): Promise<string | null>;
  set(orgId: string, pk: string): Promise<void>;
}

export interface SyncResult {
  revision: number;
  warnings: string[];
  me: { user_id: string; role: string; status: string } | null;
  members: any[];
  org: { id: string; org_sign_pk: string } | null;
}

export class SyncManager {
  private revision = 0;
  private knownVaults = new Set<string>();
  private running: Promise<SyncResult> | null = null;
  private listeners = new Set<(r: SyncResult) => void>();
  private events: EventSource | null = null;

  constructor(
    private engine: Engine,
    private api: Api,
    private pins: PinStore,
  ) {}

  onSynced(fn: (r: SyncResult) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  reset(): void {
    this.revision = 0;
    this.knownVaults.clear();
    this.stopEvents();
  }

  /** Coalesces concurrent calls. `full` re-downloads everything (e.g. after unlock). */
  sync(full = false): Promise<SyncResult> {
    if (this.running) return this.running;
    this.running = this.doSync(full).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async doSync(full: boolean): Promise<SyncResult> {
    const since = full ? 0 : this.revision;
    const data = await this.api.sync(since);
    // A vault we have never seen (newly granted) holds items whose revisions predate
    // our cursor, so an incremental pull would never return them: re-pull everything.
    const vaultIds: string[] = (data.vaults ?? []).map((v: { id: string }) => v.id);
    const gainedVault = since > 0 && vaultIds.some((id) => !this.knownVaults.has(id));
    this.knownVaults = new Set(vaultIds);
    if (gainedVault) return this.doSync(true);
    let pinned: string | null = null;
    if (data.org) {
      pinned = await this.pins.get(data.org.id);
      if (!pinned) {
        await this.pins.set(data.org.id, data.org.org_sign_pk);
        pinned = data.org.org_sign_pk;
      }
    }
    const applied = await this.engine.call<{ warnings: string[] }>("sync_apply", { ...data, pinned_org_pk: pinned });
    this.revision = data.revision;
    const result: SyncResult = {
      revision: data.revision,
      warnings: applied.warnings,
      me: data.me ?? null,
      members: data.members ?? [],
      org: data.org ?? null,
    };
    this.listeners.forEach((l) => l(result));
    return result;
  }

  /** Feed a row returned by PUT /items back into the engine without a full round trip. */
  async applyItemRows(rows: any[]): Promise<void> {
    await this.engine.call("sync_apply", { items: rows });
    for (const r of rows) this.revision = Math.max(this.revision, r.revision ?? 0);
  }

  /** Server-Sent Events: the server only says "something changed"; we then pull. */
  startEvents(url: string): void {
    this.stopEvents();
    if (typeof EventSource === "undefined") return;
    const es = new EventSource(url, { withCredentials: true });
    es.addEventListener("sync", (ev) => {
      const rev = JSON.parse((ev as MessageEvent).data).revision as number;
      if (rev > this.revision) void this.sync();
    });
    this.events = es;
  }

  stopEvents(): void {
    this.events?.close();
    this.events = null;
  }
}
