/**
 * Thin typed wrapper around the Rust engine's JSON dispatcher (core/src/engine.rs).
 * The web app runs the engine in a dedicated Worker; the extension runs it in the
 * service worker. Either way callers see the same async `call`.
 */

export type EngineTransport = (method: string, args: unknown) => Promise<unknown>;

export class EngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EngineError";
  }
}

/** Builds a transport that calls the wasm `call(method, json)` export directly. */
export function directTransport(wasmCall: (method: string, args: string) => string): EngineTransport {
  return async (method, args) => {
    const raw = JSON.parse(wasmCall(method, JSON.stringify(args ?? {}))) as { ok?: unknown; error?: string };
    if (raw.error !== undefined) throw new EngineError(raw.error);
    return raw.ok;
  };
}

export interface Engine {
  call<T = any>(method: string, args?: Record<string, unknown>): Promise<T>;
}

export function createEngine(transport: EngineTransport): Engine {
  return {
    call: <T>(method: string, args: Record<string, unknown> = {}) => transport(method, args) as Promise<T>,
  };
}

export const nowSecs = () => Math.floor(Date.now() / 1000);

// ---- shapes returned by the engine (subset used by UIs) ----

export interface KdfParams {
  m_kib: number;
  t: number;
  p: number;
}

export interface VaultSummary {
  id: string;
  kind: "personal" | "project";
  name: string;
  client_id: string | null;
  client_name: string | null;
  role: string | null;
  copy_only: boolean;
  key_version: number;
  unlocked: boolean;
  item_count: number;
}

export interface ItemSummary {
  id: string;
  vault_id: string;
  type: ItemType;
  title: string;
  subtitle: string;
  url: string | null;
  host: string | null;
  tags: string[];
  has_totp: boolean;
  updated_at: number;
  deleted_at: number | null;
  expires_at: string | null;
}

export type ItemType =
  | "login"
  | "authenticator"
  | "recovery_codes"
  | "api_key"
  | "ssh_key"
  | "server"
  | "secure_note"
  | "document";

export interface UrlEntry {
  url: string;
  match_mode?: "domain" | "host" | "exact" | "never";
  allowed_frames?: string[];
}

export interface CustomField {
  name: string;
  value: string;
  kind: "text" | "hidden" | "url" | "date";
}

export interface Item {
  title: string;
  data: { type: ItemType; [k: string]: any };
  notes?: string;
  tags?: string[];
  custom_fields?: CustomField[];
  password_history?: { value: string; replaced_at: number }[];
  attachments?: { id: string; name: string; mime: string; size: number; file_key: string }[];
  expires_at?: string | null;
}

export interface ItemDetail {
  id: string;
  vault_id: string;
  version: number;
  item: Item;
  copy_only: boolean;
  role: string | null;
  created_at: number;
  updated_at: number;
  created_by: string | null;
  updated_by: string | null;
  deleted_at: number | null;
}

export interface TotpCode {
  code: string;
  remaining: number;
  period: number;
}

export interface MatchResult {
  matches: (ItemSummary & { insecure: boolean })[];
  lookalike: { page_domain: string; imitates: string; reason: string } | null;
  insecure_page: boolean;
  cross_origin_frame: boolean;
}

export interface Strength {
  score: number;
  guesses_log10: number;
  crack_time: string;
  warning: string | null;
  suggestions: string[];
}
