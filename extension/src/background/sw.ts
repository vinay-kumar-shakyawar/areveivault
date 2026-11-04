/**
 * Service worker: hosts the vault engine and makes every policy decision.
 * Content scripts never receive vault data except the single credential the
 * user picked for their own frame (architecture §13).
 */

import { Api, ApiError, completeLogin, loginPassword, nowSecs, unlockLocal, type AuditEventInput, type Engine } from "@arevei/client";
import { BUNDLE_MANIFEST_URL, CLIPBOARD_CLEAR_MS, EXTRA_VAULT_ORIGINS, MENU_TOKEN_TTL_MS, PENDING_CAPTURE_TTL_MS, SYNC_INTERVAL_MINUTES, VAULT_ORIGIN } from "../shared/config";
import {
  randomToken,
  validateContentMessage,
  validateExternalMessage,
  validateMenuMessage,
  validatePromptMessage,
  type FieldKind,
  type FormKind,
} from "../shared/messages";
import { PendingStore } from "../shared/pending";
import { decideFill, isOwnExtensionPage, resolveFrame, type MatchResult } from "../shared/policy";
import { getEngine } from "./engine";
import { forgetSecretKey, loadSecretKey, saveSecretKey } from "./secretStore";
import * as store from "./store";

// Referenced directly (not via config.ts) so esbuild folds it to a literal and the
// E2E-only code paths below are removed from release bundles.
declare const __E2E__: boolean;

// ------------------------------------------------------------------ state

interface MenuCtx {
  token: string;
  tabId: number;
  frameId: number;
  url: string;
  topUrl?: string;
  field: FieldKind;
  formKind: FormKind;
  createdAt: number;
  visible: boolean;
}

const pending = new PendingStore(PENDING_CAPTURE_TTL_MS);
const menus = new Map<string, MenuCtx>();
const externalPorts = new Set<chrome.runtime.Port>();
let auditQueue: AuditEventInput[] = [];
let memToken: string | null = null;
let loginCtx: { email: string; secretKey: string; mfaToken: string } | null = null;
let restoring: Promise<boolean> | null = null;

// MV3 may terminate the service worker at any moment. Menu contexts and pending
// captures are mirrored to chrome.storage.session (memory-only, trusted contexts
// only — the same store that already holds the unlocked engine session).
let hydrated: Promise<void> | null = null;
function hydrate(): Promise<void> {
  hydrated ??= (async () => {
    const s = await chrome.storage.session.get(["menus", "pending"]);
    for (const c of (s.menus as MenuCtx[] | undefined) ?? []) if (!menus.has(c.token)) menus.set(c.token, c);
    pending.load((s.pending as any[] | undefined) ?? []);
  })();
  return hydrated;
}
async function persistVolatile(): Promise<void> {
  const now = Date.now();
  for (const [t, c] of menus) if (now - c.createdAt > MENU_TOKEN_TTL_MS) menus.delete(t);
  await chrome.storage.session.set({ menus: [...menus.values()], pending: pending.toJSON() });
}

const api = new Api({
  baseUrl: VAULT_ORIGIN,
  getToken: async () => memToken ?? (await store.getAccount())?.token ?? null,
});

// ------------------------------------------------------------------ backend (real or __E2E__-local)

let e2eRevision = 0;
async function putItem(req: any): Promise<any> {
  if (__E2E__) {
    const acct = await store.getAccount();
    const t = nowSecs();
    return { ...req, revision: ++e2eRevision, created_at: t, updated_at: t, created_by: acct?.userId, updated_by: acct?.userId, deleted_at: null };
  }
  return api.putItem(req);
}

// ------------------------------------------------------------------ engine lifecycle

async function engine(): Promise<Engine> {
  return getEngine();
}

async function isUnlocked(): Promise<boolean> {
  const e = await engine();
  const s = await e.call<{ unlocked: boolean }>("status");
  if (s.unlocked) return true;
  // Service worker restarted: restore the unlocked session from memory-only storage.
  if (!restoring) {
    restoring = (async () => {
      const blob = await store.getSessionBlob();
      if (!blob) return false;
      try {
        await e.call("import_session", { session: blob });
        await applyCache();
        return true;
      } catch {
        await store.setSessionBlob(null);
        return false;
      }
    })().finally(() => (restoring = null));
  }
  return restoring;
}

async function persistSession(): Promise<void> {
  const e = await engine();
  const { session } = await e.call<{ session: string }>("export_session");
  await store.setSessionBlob(session);
}

/** Feed the full ciphertext cache to the engine (the engine expects full lists). */
async function applyCache(): Promise<string[]> {
  const e = await engine();
  const c = await store.getCache();
  let pinned: string | null = null;
  if (c.org) {
    pinned = await store.getPin(c.org.id);
    if (!pinned) {
      await store.setPin(c.org.id, c.org.org_sign_pk);
      pinned = c.org.org_sign_pk;
    }
  }
  const r = await e.call<{ warnings: string[] }>("sync_apply", {
    org: c.org,
    members: c.members,
    vaults: c.vaults,
    clients: c.clients,
    grants: c.grants,
    items: Object.values(c.items),
    purged_item_ids: [],
    pinned_org_pk: pinned,
  });
  return r.warnings;
}

async function syncNow(full = false): Promise<void> {
  if (__E2E__ || !(await isUnlocked())) return;
  const c = await store.getCache();
  let data: any;
  try {
    data = await api.sync(full ? 0 : c.revision);
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) await signOut(false);
    return;
  }
  // A newly granted vault's items carry revisions older than our cursor, so an
  // incremental pull would never return them: re-pull everything in that case.
  if (!full && c.revision > 0) {
    const known = new Set(c.vaults.map((v: any) => v.id));
    if ((data.vaults ?? []).some((v: any) => !known.has(v.id))) return syncNow(true);
  }
  const next: store.SyncCache = {
    revision: data.revision,
    org: data.org ?? null,
    me: data.me ?? null,
    members: data.members ?? [],
    vaults: data.vaults ?? [],
    clients: data.clients ?? [],
    grants: data.grants ?? [],
    items: full ? {} : { ...c.items },
  };
  for (const row of data.items ?? []) next.items[row.id] = row;
  for (const id of data.purged_item_ids ?? []) delete next.items[id];
  const vaultIds = new Set<string>([...(next.vaults.map((v: any) => v.id) as string[]), (await store.getAccount())?.userId ?? ""]);
  for (const [id, row] of Object.entries(next.items)) if (!vaultIds.has(row.vault_id)) delete next.items[id];
  await store.setCache(next);
  await applyCache();
}

async function storeRow(row: any): Promise<void> {
  const c = await store.getCache();
  c.items[row.id] = row;
  c.revision = Math.max(c.revision, row.revision ?? 0);
  await store.setCache(c);
  await applyCache();
  void syncNow();
}

async function touch(): Promise<void> {
  const s = await store.getSettings();
  await chrome.alarms.create("autolock", { delayInMinutes: Math.max(1, s.autolockMinutes) });
}

async function lock(): Promise<void> {
  if (__E2E__) (self as any).__e2eLockCount++;
  const e = await engine();
  await e.call("lock");
  await store.setSessionBlob(null);
  menus.clear();
  pending.clear();
  await chrome.storage.session.remove(["menus", "pending"]);
  loginCtx = null;
  await chrome.alarms.clear("autolock");
  for (const p of externalPorts) {
    try {
      p.postMessage({ type: "locked" });
    } catch {
      externalPorts.delete(p);
    }
  }
}

async function signOut(callServer = true): Promise<void> {
  if (callServer && !__E2E__) {
    try {
      await api.logout();
    } catch {
      /* already invalid */
    }
  }
  await lock();
  memToken = null;
  await store.setAccount(null);
  await store.setCache(store.emptyCache());
  await forgetSecretKey();
}

// ------------------------------------------------------------------ audit

function audit(ev: Omit<AuditEventInput, "client_ts">): void {
  if (__E2E__) return;
  auditQueue.push({ ...ev, client_ts: nowSecs() });
  if (auditQueue.length >= 20) void flushAudit();
}

async function flushAudit(): Promise<void> {
  if (!auditQueue.length) return;
  const batch = auditQueue.splice(0, 100);
  try {
    await api.reportEvents(batch);
  } catch {
    auditQueue = [...batch, ...auditQueue].slice(0, 500);
  }
}

// ------------------------------------------------------------------ clipboard (offscreen)

async function copyToClipboard(text: string): Promise<void> {
  const url = "offscreen.html";
  const contexts = await (chrome.runtime as any).getContexts?.({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
  if (!contexts?.length) {
    await chrome.offscreen.createDocument({
      url,
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: "Copy credentials and clear the clipboard after 30 seconds",
    });
  }
  await chrome.runtime.sendMessage({ target: "offscreen", type: "copy", text, clearAfterMs: CLIPBOARD_CLEAR_MS });
}

// ------------------------------------------------------------------ matching / filling

async function matchFor(url: string, topUrl?: string): Promise<MatchResult & { matches: any[] }> {
  const e = await engine();
  return e.call("match_url", { url, top_url: topUrl ?? null });
}

async function sendFill(ctx: { tabId: number; frameId: number; field: FieldKind; url: string }, itemId: string, allowInsecure: boolean) {
  const e = await engine();
  const data = await e.call<{ username: string; password: string; totp: string | null }>("fill_data", {
    item_id: itemId,
    url: ctx.url,
    now: nowSecs(),
    allow_insecure: allowInsecure,
  });
  await chrome.tabs.sendMessage(ctx.tabId, { type: "fill", field: ctx.field, ...data }, { frameId: ctx.frameId });
  audit({ event_type: "autofill", target_type: "item", target_id: itemId });
}

function menuItems(m: MatchResult & { matches: any[] }, field: FieldKind) {
  return m.matches
    .filter((x) => field !== "otp" || x.has_totp)
    .map((x) => ({ id: x.id, title: x.title, subtitle: x.subtitle, insecure: x.insecure, hasTotp: x.has_totp }));
}

function senderFrame(sender: chrome.runtime.MessageSender) {
  if (!sender.tab?.id || sender.frameId === undefined || !sender.url) return null;
  const f = resolveFrame({ url: sender.url, origin: (sender as any).origin, frameId: sender.frameId, topUrl: sender.tab.url });
  return f ? { ...f, tabId: sender.tab.id, frameId: sender.frameId } : null;
}

async function writableVaults(): Promise<any[]> {
  const e = await engine();
  const lv = await e.call<{ vaults: any[]; org_admin: boolean }>("list_vaults");
  return lv.vaults
    .filter((v) => v.unlocked && (v.kind === "personal" || lv.org_admin || v.role === "manager" || v.role === "member"))
    .map((v) => ({ id: v.id, name: v.name, client_name: v.client_name, kind: v.kind }));
}

// ------------------------------------------------------------------ capture (save / update)

async function handleCapture(tabId: number, url: string, username: string, password: string, formKind: FormKind): Promise<string | null> {
  if (!/^https?:/i.test(url)) return null;
  if (pending.isDuplicate(tabId, username, password)) {
    const p = pending.forTab(tabId)!;
    return p.shown ? null : p.token;
  }
  const e = await engine();
  const info = await e.call<{ registrable_domain: string | null; host: string } | null>("parse_url", { url });
  const domain = info?.registrable_domain ?? info?.host;
  if (!domain || (await store.isNeverSite(domain))) return null;

  let kind: "save" | "update" = "save";
  let itemId: string | undefined;
  let itemTitle: string | undefined;
  if (await isUnlocked()) {
    const m = await matchFor(url);
    if (m.lookalike) return null;
    const candidates = m.matches.filter((x: any) => x.type === "login");
    const sameUser = candidates.filter((x: any) => username && (x.subtitle ?? "").toLowerCase() === username.toLowerCase());
    const target = sameUser[0] ?? (formKind === "change" && candidates.length === 1 ? candidates[0] : undefined);
    if (target) {
      const detail = await e.call<any>("get_item", { id: target.id });
      if (detail.item.data.password === password) return null;
      kind = "update";
      itemId = target.id;
      itemTitle = target.title;
    }
  }
  const p = pending.put({ token: randomToken(), tabId, url, username, password, kind, itemId, itemTitle });
  return p.token;
}

// ------------------------------------------------------------------ content script messages

chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  if ((raw as any)?.target === "offscreen") return false;
  const handler = sender.tab && !isOwnExtensionPage(sender, chrome.runtime.id) ? onContentMessage(raw, sender) : onPageMessage(raw, sender);
  handler.then(sendResponse, (err) => sendResponse({ error: String(err?.message ?? err) }));
  return true;
});

async function onContentMessage(raw: unknown, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const msg = validateContentMessage(raw);
  if (!msg) return { error: "invalid message" };
  await hydrate();
  try {
    return await handleContent(msg, sender);
  } finally {
    await persistVolatile();
  }
}

async function handleContent(msg: NonNullable<ReturnType<typeof validateContentMessage>>, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const frame = senderFrame(sender);
  switch (msg.type) {
    case "cs:hello": {
      if (sender.frameId !== 0 || !sender.tab?.id) return {};
      // Re-show an undecided capture on the next page (the form usually navigates away
      // right after submit, destroying the prompt that was opened on the old page).
      const p = pending.forTab(sender.tab.id);
      return p && (!p.shown || Date.now() - p.createdAt < 60_000) ? { prompt: p.token, kind: p.kind } : {};
    }
    case "cs:open-menu":
    case "cs:shortcut-fill": {
      if (!frame) return { error: "unsupported frame" };
      const ctx: MenuCtx = {
        token: randomToken(),
        tabId: frame.tabId,
        frameId: frame.frameId,
        url: frame.url,
        topUrl: frame.topUrl,
        field: msg.field,
        formKind: msg.formKind,
        createdAt: Date.now(),
        visible: true,
      };
      if (msg.type === "cs:shortcut-fill" && (await isUnlocked())) {
        await touch();
        const m = await matchFor(ctx.url, ctx.topUrl);
        const items = menuItems(m, ctx.field);
        if (items.length === 1 && decideFill(m, items[0].id, { visible: true, confirmInsecure: false }).ok) {
          await sendFill(ctx, items[0].id, false);
          return { filled: true };
        }
      }
      for (const [t, c] of menus) if (Date.now() - c.createdAt > MENU_TOKEN_TTL_MS || c.tabId === ctx.tabId) menus.delete(t);
      menus.set(ctx.token, ctx);
      if (await isUnlocked()) await touch();
      return { token: ctx.token };
    }
    case "cs:menu-visibility": {
      const ctx = menus.get(msg.token);
      if (ctx && ctx.tabId === sender.tab?.id) ctx.visible = msg.visible;
      return {};
    }
    case "cs:close-menu":
      menus.delete(msg.token);
      return {};
    case "cs:capture": {
      if (!frame) return {};
      const token = await handleCapture(frame.tabId, frame.url, msg.username, msg.password, msg.formKind);
      const p = token ? pending.byToken(token) : undefined;
      return token ? { prompt: token, kind: p?.kind } : {};
    }
  }
}

// ------------------------------------------------------------------ inline menu & prompt (extension iframes)

chrome.runtime.onConnect.addListener((port) => {
  const s = port.sender;
  if (!s || s.id !== chrome.runtime.id) return port.disconnect();
  if (port.name === "menu" && isOwnExtensionPage(s, chrome.runtime.id, "menu.html") && s.tab?.id) {
    port.onMessage.addListener((m) => void onMenuMessage(port, s.tab!.id!, m));
  } else if (port.name === "prompt" && isOwnExtensionPage(s, chrome.runtime.id, "prompt.html") && s.tab?.id) {
    port.onMessage.addListener((m) => void onPromptMessage(port, s.tab!.id!, m));
  } else if (port.name === "popup" && isOwnExtensionPage(s, chrome.runtime.id, "popup.html")) {
    // Keeps the service worker alive while the popup is open (sign-in + MFA).
    port.onMessage.addListener(() => void touch());
  } else {
    port.disconnect();
  }
});

async function onMenuMessage(port: chrome.runtime.Port, tabId: number, raw: unknown) {
  const msg = validateMenuMessage(raw);
  if (!msg) return;
  await hydrate();
  try {
    await handleMenu(port, tabId, msg);
  } finally {
    await persistVolatile();
  }
}

async function handleMenu(port: chrome.runtime.Port, tabId: number, msg: NonNullable<ReturnType<typeof validateMenuMessage>>) {
  const ctx = menus.get(msg.token);
  // The menu iframe must live in the same tab the menu was opened for.
  if (!ctx || ctx.tabId !== tabId || Date.now() - ctx.createdAt > MENU_TOKEN_TTL_MS) {
    port.postMessage({ type: "error", message: "This menu has expired." });
    return;
  }
  const reply = (m: unknown) => port.postMessage(m);
  if (msg.type === "menu:close") {
    menus.delete(ctx.token);
    void chrome.tabs.sendMessage(ctx.tabId, { type: "close-menu" }, { frameId: ctx.frameId }).catch(() => {});
    return;
  }
  const canGenerate = ctx.field === "new-password" || (ctx.field === "password" && (ctx.formKind === "signup" || ctx.formKind === "change"));
  if (msg.type === "menu:generate") {
    if (!msg.visible || !ctx.visible) return reply({ type: "error", message: "The menu is covered by another element. Close it and try again." });
    const e = await engine();
    const g = await e.call<{ value: string }>("generate_password");
    await chrome.tabs.sendMessage(ctx.tabId, { type: "fill-generated", password: g.value }, { frameId: ctx.frameId });
    menus.delete(ctx.token);
    return reply({ type: "done" });
  }
  if (!(await isUnlocked())) return reply({ type: "state", state: "locked", canGenerate: false });
  await touch();
  const m = await matchFor(ctx.url, ctx.topUrl);
  if (msg.type === "menu:init") {
    const host = (() => {
      try {
        return new URL(ctx.url).host;
      } catch {
        return "";
      }
    })();
    return reply({
      type: "state",
      state: "ok",
      host,
      field: ctx.field,
      items: menuItems(m, ctx.field),
      lookalike: m.lookalike,
      insecurePage: m.insecure_page,
      crossOrigin: m.cross_origin_frame,
      canGenerate,
    });
  }
  if (msg.type === "menu:select") {
    const d = decideFill(m, msg.itemId, { visible: msg.visible && ctx.visible, confirmInsecure: msg.confirmInsecure });
    if (!d.ok) return reply({ type: "refused", reason: d.reason, itemId: msg.itemId });
    try {
      await sendFill(ctx, msg.itemId, msg.confirmInsecure);
      menus.delete(ctx.token);
      reply({ type: "done" });
    } catch (e: any) {
      reply({ type: "error", message: e?.message ?? "Fill failed" });
    }
  }
}

async function onPromptMessage(port: chrome.runtime.Port, tabId: number, raw: unknown) {
  const msg = validatePromptMessage(raw);
  if (!msg) return;
  await hydrate();
  try {
    await handlePrompt(port, tabId, msg);
  } finally {
    await persistVolatile();
  }
}

async function handlePrompt(port: chrome.runtime.Port, tabId: number, msg: NonNullable<ReturnType<typeof validatePromptMessage>>) {
  const p = pending.byToken(msg.token);
  const reply = (m: unknown) => port.postMessage(m);
  if (!p || p.tabId !== tabId) return reply({ type: "error", message: "This prompt has expired." });
  const close = () => {
    pending.remove(p.token);
    void chrome.tabs.sendMessage(tabId, { type: "close-prompt" }, { frameId: 0 }).catch(() => {});
  };
  const host = new URL(p.url).host;
  switch (msg.type) {
    case "prompt:init": {
      p.shown = true;
      if (!(await isUnlocked())) return reply({ type: "state", state: "locked", host, kind: p.kind });
      await touch();
      return reply({
        type: "state",
        state: "ok",
        kind: p.kind,
        host,
        username: p.username,
        itemTitle: p.itemTitle ?? null,
        vaults: p.kind === "save" ? await writableVaults() : [],
      });
    }
    case "prompt:dismiss":
      return close();
    case "prompt:never": {
      const e = await engine();
      const info = await e.call<any>("parse_url", { url: p.url });
      await store.addNeverSite(info?.registrable_domain ?? info?.host);
      return close();
    }
    case "prompt:save":
    case "prompt:update": {
      if (!msg.visible) return reply({ type: "error", message: "The prompt is covered by another element." });
      if (!(await isUnlocked())) return reply({ type: "error", message: "Unlock Arevei Vault first." });
      const e = await engine();
      try {
        let req: any;
        if (msg.type === "prompt:save") {
          const origin = new URL(p.url).origin;
          req = await e.call("encrypt_item", {
            vault_id: msg.vaultId,
            item: {
              title: msg.title.trim() || host,
              data: { type: "login", username: p.username, password: p.password, urls: [{ url: origin }] },
            },
            now: nowSecs(),
          });
        } else {
          const detail = await e.call<any>("get_item", { id: p.itemId });
          const item = { ...detail.item, data: { ...detail.item.data, password: p.password } };
          req = await e.call("encrypt_item", { vault_id: detail.vault_id, item_id: p.itemId, item, now: nowSecs() });
        }
        const row = await putItem(req);
        await storeRow(row);
        reply({ type: "done", kind: msg.type === "prompt:save" ? "saved" : "updated" });
        setTimeout(() => {
          close();
          void persistVolatile();
        }, 1200);
      } catch (err: any) {
        reply({ type: "error", message: err instanceof ApiError && err.status === 409 ? "The item changed elsewhere; try again." : err?.message ?? "Save failed" });
      }
    }
  }
}

// ------------------------------------------------------------------ popup & onboarding RPC

async function onPageMessage(raw: any, sender: chrome.runtime.MessageSender): Promise<unknown> {
  if (!isOwnExtensionPage(sender, chrome.runtime.id, "popup.html") && !isOwnExtensionPage(sender, chrome.runtime.id, "onboarding.html")) {
    return { error: "forbidden" };
  }
  if (raw?.target !== "sw" || typeof raw.method !== "string") return { error: "invalid" };
  const a = raw.args ?? {};
  const e = await engine();
  switch (raw.method) {
    case "state": {
      const acct = await store.getAccount();
      const unlocked = acct ? await isUnlocked() : false;
      return {
        signedIn: !!acct,
        unlocked,
        email: acct?.email ?? null,
        hasSecretKey: acct ? !!(await loadSecretKey(acct.email)) : false,
        mfaPending: !!loginCtx,
        vaultOrigin: VAULT_ORIGIN,
        settings: await store.getSettings(),
      };
    }
    case "signin": {
      const { email, password, secretKey } = a as { email: string; password: string; secretKey: string };
      const v = await e.call<{ valid: boolean }>("validate_secret_key", { secret_key: secretKey });
      if (!v.valid) return { error: "That Secret Key isn't valid. Check your Emergency Kit." };
      try {
        const r = await loginPassword(e, api, email, password, secretKey);
        loginCtx = { email: email.trim().toLowerCase(), secretKey, mfaToken: r.mfaToken };
        return { mfa: r.methods };
      } catch (err) {
        return { error: "Sign-in failed. Check your email, master password and Secret Key." + (err instanceof ApiError && err.status === 429 ? " Too many attempts; wait and retry." : "") };
      }
    }
    case "mfa": {
      if (!loginCtx) return { error: "Start sign-in again." };
      try {
        const s = await api.verifyMfa({ mfa_token: loginCtx.mfaToken, code: String(a.code ?? ""), device_name: deviceName() });
        memToken = s.session_token;
        await completeLogin(e, api);
        const keyset = await api.keyset();
        await store.setAccount({ email: loginCtx.email, userId: s.user_id, token: s.session_token, keyset });
        await saveSecretKey(loginCtx.email, loginCtx.secretKey);
        loginCtx = null;
        memToken = null;
        await persistSession();
        await touch();
        await syncNow(true);
        return { ok: true };
      } catch (err) {
        return { error: err instanceof ApiError && err.status === 401 ? "Incorrect code." : "Verification failed." };
      }
    }
    case "unlock": {
      const acct = await store.getAccount();
      if (!acct) return { error: "Not signed in." };
      const sk = (a.secretKey as string | undefined) || (await loadSecretKey(acct.email));
      if (!sk) return { error: "Enter your Secret Key." };
      try {
        await unlockLocal(e, acct.keyset, String(a.password ?? ""), sk);
      } catch {
        return { error: "Incorrect master password." };
      }
      if (a.secretKey) await saveSecretKey(acct.email, sk);
      await persistSession();
      await applyCache();
      await touch();
      void syncNow();
      notifyExternal({ type: "unlocked" });
      return { ok: true };
    }
    case "lock":
      await lock();
      return { ok: true };
    case "signout":
      await signOut();
      return { ok: true };
    case "tabMatches": {
      if (!(await isUnlocked())) return { error: "locked" };
      await touch();
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || !/^https?:/.test(tab.url)) return { matches: [], lookalike: null, insecure_page: false, url: tab?.url ?? null };
      const m = await matchFor(tab.url);
      return { ...m, url: tab.url };
    }
    case "listItems": {
      if (!(await isUnlocked())) return { error: "locked" };
      await touch();
      const items = await e.call<any[]>("list_items", { query: String(a.query ?? "") });
      return { items: items.slice(0, 100) };
    }
    case "totp": {
      if (!(await isUnlocked())) return { error: "locked" };
      return e.call("totp", { item_id: String(a.itemId), now: nowSecs() });
    }
    case "copy": {
      if (!(await isUnlocked())) return { error: "locked" };
      await touch();
      const field = String(a.field);
      const id = String(a.itemId);
      let value = "";
      if (field === "totp") value = (await e.call<{ code: string }>("totp", { item_id: id, now: nowSecs() })).code;
      else {
        const d = await e.call<any>("get_item", { id });
        value = field === "username" ? (d.item.data.username ?? d.item.data.account ?? "") : (d.item.data.password ?? d.item.data.secret ?? "");
      }
      audit({ event_type: field === "totp" ? "totp_copy" : "item_copy", target_type: "item", target_id: id });
      // Firefox has no offscreen documents: the popup writes the clipboard itself.
      if (!chrome.offscreen) return { ok: true, value };
      await copyToClipboard(value);
      return { ok: true };
    }
    case "settings": {
      const s = { autolockMinutes: Math.min(60, Math.max(1, Number(a.autolockMinutes) || 5)) };
      await store.setSettings(s);
      await touch();
      return { ok: true };
    }
    case "importCsv": {
      if (!(await isUnlocked())) return { error: "Unlock first." };
      const acct = await store.getAccount();
      const parsed = await e.call<{ items: any[]; skipped: string[] }>("import_parse", { format: a.format ?? "chrome", text: String(a.text ?? "") });
      let imported = 0;
      const c = await store.getCache();
      for (const it of parsed.items) {
        const req = await e.call("encrypt_item", { vault_id: acct!.userId, item: it.item, now: nowSecs() });
        const row = await putItem(req);
        c.items[row.id] = row;
        c.revision = Math.max(c.revision, row.revision ?? 0);
        imported++;
      }
      await store.setCache(c);
      await applyCache();
      void syncNow();
      return { imported, skipped: parsed.skipped };
    }
    default:
      return { error: "unknown method" };
  }
}

function deviceName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : "Browser";
  return `Arevei Vault extension (${browser})`;
}

// ------------------------------------------------------------------ vault web app (externally_connectable)

function isVaultOrigin(origin: string | undefined): boolean {
  if (!origin) return false;
  return origin === VAULT_ORIGIN || EXTRA_VAULT_ORIGINS.includes(origin);
}

function notifyExternal(m: unknown) {
  for (const p of externalPorts) {
    try {
      p.postMessage(m);
    } catch {
      externalPorts.delete(p);
    }
  }
}

chrome.runtime.onMessageExternal?.addListener((raw, sender, sendResponse) => {
  if (!isVaultOrigin((sender as any).origin ?? (sender.url ? new URL(sender.url).origin : undefined))) return false;
  const msg = validateExternalMessage(raw);
  if (!msg) return false;
  void (async () => {
    if (msg.type === "lock-now" || msg.type === "locked") {
      await lock();
      sendResponse({ ok: true });
    } else if (msg.type === "verify-build") {
      sendResponse(await verifyBuild());
    } else {
      sendResponse({ ok: true });
    }
  })();
  return true;
});

chrome.runtime.onConnectExternal?.addListener((port) => {
  const origin = (port.sender as any)?.origin ?? (port.sender?.url ? new URL(port.sender.url).origin : undefined);
  if (!isVaultOrigin(origin)) return port.disconnect();
  externalPorts.add(port);
  port.onDisconnect.addListener(() => externalPorts.delete(port));
  port.onMessage.addListener((raw) => {
    const msg = validateExternalMessage(raw);
    if (msg && (msg.type === "lock-now" || msg.type === "locked")) void lock();
  });
});

/** Compares the served web bundle with the signed, published manifest (architecture §12.3). */
async function verifyBuild(): Promise<{ status: "verified" | "mismatch" | "unverified" | "error"; mismatches?: string[] }> {
  if (!BUNDLE_MANIFEST_URL) return { status: "unverified" };
  try {
    const manifest = (await (await fetch(BUNDLE_MANIFEST_URL, { cache: "no-store" })).json()) as { files: Record<string, string> };
    const sha = async (buf: ArrayBuffer) =>
      Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)), (b) => b.toString(16).padStart(2, "0")).join("");
    const htmlBuf = await (await fetch(`${VAULT_ORIGIN}/`, { cache: "no-store", credentials: "omit" })).arrayBuffer();
    const mismatches: string[] = [];
    if (manifest.files["index.html"] !== (await sha(htmlBuf))) mismatches.push("index.html");
    const html = new TextDecoder().decode(htmlBuf);
    const refs = [...html.matchAll(/<(?:script|link)\b[^>]*?(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]);
    for (const ref of refs) {
      const key = ref.replace(/^\//, "");
      const buf = await (await fetch(`${VAULT_ORIGIN}${ref}`, { cache: "no-store", credentials: "omit" })).arrayBuffer();
      if (manifest.files[key] !== (await sha(buf))) mismatches.push(key);
    }
    return { status: mismatches.length ? "mismatch" : "verified", mismatches };
  } catch {
    return { status: "error" };
  }
}

// ------------------------------------------------------------------ alarms, idle, commands, context menus, install

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "autolock") void lock();
  if (a.name === "sync") {
    pending.sweep();
    void flushAudit();
    void syncNow();
  }
});
void chrome.alarms.create("sync", { periodInMinutes: SYNC_INTERVAL_MINUTES });

chrome.idle.setDetectionInterval(60);
chrome.idle.onStateChanged.addListener((state) => {
  if (state === "locked") void lock();
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command === "fill-login" && tab?.id) void chrome.tabs.sendMessage(tab.id, { type: "shortcut" }).catch(() => {});
});

chrome.runtime.onInstalled.addListener((details) => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "fill-login", title: "Fill login", contexts: ["editable"] });
    chrome.contextMenus.create({ id: "generate-password", title: "Generate password", contexts: ["editable"] });
    chrome.contextMenus.create({ id: "copy-totp", title: "Copy one-time code", contexts: ["page", "editable"] });
  });
  if (details.reason === "install" && !__E2E__) void chrome.tabs.create({ url: chrome.runtime.getURL("onboarding.html") });
  // Inject into tabs that were already open (content scripts only run on new loads otherwise).
  void chrome.tabs.query({ url: ["http://*/*", "https://*/*"] }).then((tabs) => {
    for (const t of tabs) {
      if (t.id) void chrome.scripting.executeScript({ target: { tabId: t.id, allFrames: true }, files: ["content.js"] }).catch(() => {});
    }
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab?.id) return;
  const frameId = info.frameId ?? 0;
  void (async () => {
    if (info.menuItemId === "fill-login") {
      await chrome.tabs.sendMessage(tab.id!, { type: "shortcut" }, { frameId }).catch(() => {});
    } else if (info.menuItemId === "generate-password") {
      const e = await engine();
      const g = await e.call<{ value: string }>("generate_password");
      await chrome.tabs.sendMessage(tab.id!, { type: "fill-generated", password: g.value }, { frameId }).catch(() => {});
    } else if (info.menuItemId === "copy-totp" && tab.url && (await isUnlocked())) {
      const m = await matchFor(tab.url);
      const withTotp = m.lookalike ? [] : m.matches.filter((x: any) => x.has_totp);
      if (withTotp.length === 1) {
        const e = await engine();
        const { code } = await e.call<{ code: string }>("totp", { item_id: withTotp[0].id, now: nowSecs() });
        await copyToClipboard(code);
        audit({ event_type: "totp_copy", target_type: "item", target_id: withTotp[0].id });
      }
    }
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pending.clearTab(tabId);
  for (const [t, c] of menus) if (c.tabId === tabId) menus.delete(t);
});

// ------------------------------------------------------------------ __E2E__-only seeding hook (compiled out of release builds)

if (__E2E__) {
  (self as any).__e2eBootedAt = Date.now();
  (self as any).__e2eLockCount = 0;
  (self as any).__e2eSeed = async (items: { title: string; url: string; username: string; password: string; totp?: string }[]) => {
    const e = await engine();
    const { secret_key } = await e.call<{ secret_key: string }>("generate_secret_key");
    const params = await e.call<any>("new_account_params");
    await e.call("derive", { password: "__E2E__-Master-Password-1!", secret_key, salt: params.salt, kdf: params.kdf });
    const userId = crypto.randomUUID();
    const acct = await e.call<any>("create_account", { user_id: userId, email: "e2e@arevei.test", salt: params.salt, kdf: params.kdf, now: nowSecs() });
    await store.setAccount({ email: "e2e@arevei.test", userId, token: "e2e", keyset: acct.keyset });
    const cache = store.emptyCache();
    await store.setCache(cache);
    for (const it of items) {
      const req = await e.call("encrypt_item", {
        vault_id: userId,
        item: { title: it.title, data: { type: "login", username: it.username, password: it.password, urls: [{ url: it.url }], totp: it.totp ?? null } },
        now: nowSecs(),
      });
      const row = await putItem(req);
      cache.items[row.id] = row;
    }
    await store.setCache(cache);
    await applyCache();
    await persistSession();
    await touch();
    return { userId };
  };
  (self as any).__e2eItems = async () => (await engine()).call("list_items", {});
  (self as any).__e2eGetItem = async (id: string) => (await engine()).call("get_item", { id });
}
