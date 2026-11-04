/**
 * Application controller: owns the crypto Worker transport, API client, sync, and
 * session lifecycle. React reads it through `useApp()` (useSyncExternalStore).
 */
import { useSyncExternalStore } from "react";
import {
  Api,
  ApiError,
  SyncManager,
  completeLogin,
  createEngine,
  loginPassword,
  nowSecs,
  signup as signupFlow,
  unlockLocal,
  type Engine,
  type Item,
  type Session,
  type SignupInput,
  type SignupPending,
  type SyncResult,
} from "@arevei/client";
import { AuditQueue } from "./audit";
import { startAutoLock } from "./autolock";
import { ClipboardManager, browserClipboardDeps } from "./clipboard";
import { accountStore, pinStore } from "./idb";
import { createWorkerTransport, type WorkerTransport } from "./rpc";
import { secretKeyStore } from "./secretKeyStore";
import { settings } from "./settings";
import { toast } from "./toast";
import { trustedWorkerUrl } from "./trustedTypes";
import cryptoWorkerUrl from "../crypto.worker.ts?worker&url";

export type Phase = "boot" | "signed_out" | "locked" | "unlocked";

export interface Prefs {
  favorites: string[];
}

export interface AppState {
  phase: Phase;
  session: Session | null;
  sync: SyncResult | null;
  /** Bumps whenever vault data changes; queries re-run on change. */
  version: number;
  prefs: Prefs;
  warnings: string[];
}

export class ConflictError extends Error {
  constructor() {
    super("This item was changed elsewhere. The latest version has been loaded — review it and save again.");
  }
}

let transport: WorkerTransport | null = null;
let stopAutoLock: (() => void) | null = null;

function newTransport(): WorkerTransport {
  // Worker construction is a Trusted Types sink; the URL goes through our single policy.
  const w = new Worker(trustedWorkerUrl(cryptoWorkerUrl), { type: "module", name: "arevei-crypto" });
  return createWorkerTransport(w);
}

transport = newTransport();
export const engine: Engine = createEngine((m, a) => transport!.call(m, a));

export const api = new Api({
  baseUrl: "",
  onUnauthorized: () => {
    if (state.phase === "unlocked") lock("Your session ended. Sign in again.");
  },
});

export const sync = new SyncManager(engine, api, pinStore);
export const clipboard = new ClipboardManager(browserClipboardDeps());
export const audit = new AuditQueue(() => (state.phase === "unlocked" ? api : null));

// ---------------- store ----------------
let state: AppState = { phase: "boot", session: null, sync: null, version: 0, prefs: { favorites: [] }, warnings: [] };
const listeners = new Set<() => void>();
function set(patch: Partial<AppState>) {
  state = { ...state, ...patch };
  listeners.forEach((l) => l());
}
export const getState = () => state;
export function useApp(): AppState {
  return useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => state,
  );
}
export const bump = () => set({ version: state.version + 1 });

sync.onSynced((r) => {
  set({ sync: r, version: state.version + 1, warnings: r.warnings });
  if (r.me && state.session && (r.me.role !== state.session.role || r.me.status !== state.session.status)) {
    set({ session: { ...state.session, role: r.me.role as Session["role"], status: r.me.status as Session["status"] } });
  }
});

export function deviceName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

// ---------------- lifecycle ----------------
export async function boot(): Promise<void> {
  try {
    const session = await api.session();
    set({ session, phase: "locked" });
  } catch {
    set({ phase: "signed_out" });
  }
}

async function cacheAccount(session: Session): Promise<void> {
  const keyset = await api.keyset();
  await accountStore.set({ email: session.email, user_id: session.user_id, keyset });
}

async function afterUnlock(session: Session): Promise<void> {
  set({ session, phase: "unlocked" });
  try {
    await sync.sync(true);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : "Sync failed");
  }
  await loadPrefs();
  sync.startEvents("/api/v1/events");
  stopAutoLock?.();
  stopAutoLock = startAutoLock({ minutes: () => settings.get().autoLockMinutes, onLock: () => lock() });
}

export async function signupStart(input: SignupInput): Promise<SignupPending> {
  return signupFlow(engine, api, input);
}

export async function signupConfirm(pending: SignupPending, email: string, code: string): Promise<void> {
  const res = await api.confirmTotp({ pending_token: pending.pendingToken, code: code.replace(/\s/g, ""), device_name: deviceName() });
  const { session_token: _t, ...session } = res;
  await cacheAccount(session);
  if (settings.get().rememberSecretKey) await secretKeyStore.save(email.trim().toLowerCase(), pending.secretKey);
  await afterUnlock(session);
}

export async function loginStart(email: string, password: string, secretKey: string) {
  return loginPassword(engine, api, email, password, secretKey);
}

export async function loginMfa(mfaToken: string, code: string, email: string, secretKey: string): Promise<void> {
  const res = await api.verifyMfa({ mfa_token: mfaToken, code: code.replace(/\s/g, ""), device_name: deviceName() });
  const { session_token: _t, ...session } = res;
  await completeLogin(engine, api);
  await cacheAccount(session);
  if (settings.get().rememberSecretKey) await secretKeyStore.save(email.trim().toLowerCase(), secretKey);
  else await secretKeyStore.clear();
  await afterUnlock(session);
}

/** Session valid, keys gone (after lock/reload): derive locally from the keyset. */
export async function unlock(password: string, secretKeyInput?: string): Promise<void> {
  const session = state.session ?? (await api.session());
  let keyset: any;
  try {
    keyset = await api.keyset();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) throw e;
    keyset = (await accountStore.get())?.keyset;
  }
  if (!keyset) throw new Error("No account data available on this device. Sign in again.");
  const secretKey = secretKeyInput || (await secretKeyStore.load(session.email));
  if (!secretKey) throw new Error("Enter your Secret Key.");
  await unlockLocal(engine, keyset, password, secretKey);
  await accountStore.set({ email: session.email, user_id: session.user_id, keyset });
  if (secretKeyInput && settings.get().rememberSecretKey) await secretKeyStore.save(session.email, secretKeyInput);
  await afterUnlock(session);
}

/** Re-authenticate an unlocked user (export, reveal Secret Key) by local re-derivation. */
export async function reauth(password: string): Promise<string> {
  const session = state.session!;
  const account = await accountStore.get();
  const secretKey = await secretKeyStore.load(session.email);
  if (!account || !secretKey) throw new Error("Re-authentication needs the Secret Key remembered on this device.");
  try {
    await unlockLocal(engine, account.keyset, password, secretKey);
  } catch {
    throw new Error("Incorrect master password.");
  }
  return secretKey;
}

/** Lock: kill the crypto worker (all keys gone), drop state, reload to purge the JS heap. */
export function lock(message?: string): void {
  void audit.flush();
  stopAutoLock?.();
  sync.stopEvents();
  transport?.terminate();
  transport = null;
  clipboard.dispose();
  if (message) sessionStorage.setItem("arevei-lock-message", message);
  location.reload();
}

export async function logout(): Promise<void> {
  try {
    await audit.flush();
    await api.logout();
  } catch {
    /* already signed out */
  }
  await accountStore.clear();
  if (!settings.get().rememberSecretKey) await secretKeyStore.clear();
  transport?.terminate();
  transport = null;
  location.replace("/");
}

// ---------------- prefs (ASK-encrypted on server) ----------------
async function loadPrefs(): Promise<void> {
  try {
    const { blob } = await api.getPrefs();
    if (blob) {
      const { prefs } = await engine.call<{ prefs: Prefs }>("decrypt_prefs", { blob });
      set({ prefs: { ...prefs, favorites: Array.isArray(prefs?.favorites) ? prefs.favorites : [] } });
    }
  } catch {
    /* no prefs yet */
  }
}

export async function savePrefs(prefs: Prefs): Promise<void> {
  set({ prefs });
  const { blob } = await engine.call<{ blob: string }>("encrypt_prefs", { prefs });
  await api.putPrefs(blob);
}

export async function toggleFavorite(id: string): Promise<void> {
  const fav = new Set(state.prefs.favorites);
  if (fav.has(id)) fav.delete(id);
  else fav.add(id);
  await savePrefs({ ...state.prefs, favorites: [...fav] });
}

// ---------------- data ----------------
export async function refresh(full = false): Promise<void> {
  await sync.sync(full);
}

/** Encrypt + PUT. On 409, re-syncs so the engine holds the latest version, then throws ConflictError. */
export async function saveItem(vaultId: string, item: Item, itemId?: string | null, newId?: string): Promise<string> {
  const req = await engine.call("encrypt_item", { vault_id: vaultId, item, item_id: itemId ?? null, new_id: newId ?? null, now: nowSecs() });
  try {
    const row = await api.putItem(req);
    await sync.applyItemRows([row]);
    bump();
    return req.id;
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      if (e.body?.current) await sync.applyItemRows([e.body.current]);
      else await sync.sync();
      bump();
      throw new ConflictError();
    }
    throw e;
  }
}

export async function moveItem(id: string, toVaultId: string): Promise<void> {
  const req = await engine.call("move_item", { id, to_vault_id: toVaultId });
  const row = await api.putItem(req);
  await sync.applyItemRows([row]);
  bump();
}

export async function trashItem(id: string): Promise<void> {
  await api.deleteItem(id);
  await sync.sync();
}

export async function restoreItem(id: string): Promise<void> {
  await api.restoreItem(id);
  await sync.sync();
}

export async function purgeItem(id: string): Promise<void> {
  await api.deleteItem(id, true);
  await sync.sync();
}

export async function copyText(text: string, label: string, audited?: { itemId: string; vaultId: string; kind?: "item_copy" | "totp_copy" }): Promise<void> {
  try {
    await clipboard.copy(text, label, settings.get().clipboardSeconds);
  } catch {
    toast.error("Clipboard access was blocked by the browser.");
    return;
  }
  if (audited) audit.record(audited.kind ?? "item_copy", audited.itemId, audited.vaultId);
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 429) return "Too many attempts. Wait a moment and try again.";
    if (e.status === 403) return e.message || "You don't have permission to do that.";
    return e.message || `Request failed (${e.status})`;
  }
  if (e instanceof Error) {
    if (/decryption failed|Opaque|authentication protocol/i.test(e.message)) return "Incorrect master password or Secret Key.";
    return e.message;
  }
  return "Something went wrong.";
}
