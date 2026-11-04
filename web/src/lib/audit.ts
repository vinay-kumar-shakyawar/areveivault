/** Batches client-reported audit events (view/reveal/copy/export) — architecture §11. */
import type { Api, AuditEventInput } from "@arevei/client";

export class AuditQueue {
  private queue: AuditEventInput[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private api: () => Api | null) {}

  record(event_type: AuditEventInput["event_type"], target_id: string, vault_id?: string | null, target_type: AuditEventInput["target_type"] = "item") {
    this.queue.push({ event_type, target_type, target_id, vault_id: vault_id ?? null, client_ts: Math.floor(Date.now() / 1000) });
    if (this.queue.length >= 20) void this.flush();
    else if (!this.timer) this.timer = setTimeout(() => void this.flush(), 4000);
  }

  async flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const api = this.api();
    if (!api || this.queue.length === 0) return;
    const batch = this.queue.splice(0, 100);
    try {
      await api.reportEvents(batch);
    } catch {
      // Best effort: keep events for the next flush (bounded).
      this.queue = [...batch, ...this.queue].slice(0, 500);
    }
  }
}
