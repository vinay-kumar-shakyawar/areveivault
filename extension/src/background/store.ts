/**
 * Persistent extension state. `chrome.storage.local` holds ONLY ciphertext and
 * non-key metadata (sync cache, encrypted keyset, session token, settings).
 * `chrome.storage.session` (memory-only, trusted contexts) holds the unlocked
 * engine session so a service-worker restart does not lock the vault, while a
 * browser restart does.
 */

export interface SyncCache {
  revision: number;
  org: any | null;
  me: any | null;
  members: any[];
  vaults: any[];
  clients: any[];
  grants: any[];
  items: Record<string, any>;
}

export interface Account {
  email: string;
  userId: string;
  /** Bearer session token. Not a key: it can't decrypt anything, and the server revokes it on logout/device removal. */
  token: string;
  keyset: any;
}

export interface Settings {
  autolockMinutes: number;
}

const local = chrome.storage.local;
const session = chrome.storage.session;

export const emptyCache = (): SyncCache => ({ revision: 0, org: null, me: null, members: [], vaults: [], clients: [], grants: [], items: {} });

export async function getAccount(): Promise<Account | null> {
  return ((await local.get("account")).account as Account | undefined) ?? null;
}
export const setAccount = (a: Account | null) => (a ? local.set({ account: a }) : local.remove("account"));

export async function getCache(): Promise<SyncCache> {
  return ((await local.get("cache")).cache as SyncCache | undefined) ?? emptyCache();
}
export const setCache = (c: SyncCache) => local.set({ cache: c });

export async function getPin(orgId: string): Promise<string | null> {
  const pins = ((await local.get("orgPins")).orgPins as Record<string, string> | undefined) ?? {};
  return pins[orgId] ?? null;
}
export async function setPin(orgId: string, pk: string): Promise<void> {
  const pins = ((await local.get("orgPins")).orgPins as Record<string, string> | undefined) ?? {};
  pins[orgId] = pk;
  await local.set({ orgPins: pins });
}

export async function getSettings(): Promise<Settings> {
  return { autolockMinutes: 5, ...(((await local.get("settings")).settings as Partial<Settings>) ?? {}) };
}
export const setSettings = (s: Settings) => local.set({ settings: s });

/** "Never save for this site": stored as SHA-256 of the registrable domain, not the domain itself. */
async function domainHash(domain: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`arevei-never:${domain}`));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
export async function isNeverSite(domain: string): Promise<boolean> {
  const list = ((await local.get("neverSites")).neverSites as string[] | undefined) ?? [];
  return list.includes(await domainHash(domain));
}
export async function addNeverSite(domain: string): Promise<void> {
  const list = ((await local.get("neverSites")).neverSites as string[] | undefined) ?? [];
  const h = await domainHash(domain);
  if (!list.includes(h)) await local.set({ neverSites: [...list, h] });
}

export async function getSessionBlob(): Promise<string | null> {
  return ((await session.get("engineSession")).engineSession as string | undefined) ?? null;
}
export const setSessionBlob = (s: string | null) => (s ? session.set({ engineSession: s }) : session.remove("engineSession"));
