/**
 * Remembers the Secret Key on this device, encrypted with a NON-EXTRACTABLE
 * WebCrypto AES-GCM key stored in the extension origin's IndexedDB. Script can
 * use the key but never read its bytes. The Secret Key alone is useless without
 * the master password (architecture §6.3).
 */

const DB = "arevei-vault";
const STORE = "kv";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idb<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await open();
  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    req.onsuccess = () => resolve(req.result as T);
    req.onerror = () => reject(req.error);
  });
}

async function wrappingKey(): Promise<CryptoKey> {
  const existing = await idb<CryptoKey | undefined>("readonly", (s) => s.get("wrap-key"));
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idb("readwrite", (s) => s.put(key, "wrap-key"));
  return key;
}

export async function saveSecretKey(email: string, secretKey: string): Promise<void> {
  const key = await wrappingKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(email) },
    key,
    new TextEncoder().encode(secretKey),
  );
  await idb("readwrite", (s) => s.put({ iv, ct, email }, "secret-key"));
}

export async function loadSecretKey(email: string): Promise<string | null> {
  const rec = await idb<{ iv: Uint8Array; ct: ArrayBuffer; email: string } | undefined>("readonly", (s) => s.get("secret-key"));
  if (!rec || rec.email !== email) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: rec.iv, additionalData: new TextEncoder().encode(email) },
      await wrappingKey(),
      rec.ct,
    );
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

export async function forgetSecretKey(): Promise<void> {
  await idb("readwrite", (s) => s.delete("secret-key"));
}

// ---- unlocked session kept across browser restarts ("Auto-lock: Never") ----
//
// The exported engine session is encrypted with the same non-extractable key, so the
// bytes on disk can't be decrypted outside this browser profile. Anyone who can use
// the profile can use the vault: that is the tradeoff the user accepts with "Never".

const SESSION_AAD = new TextEncoder().encode("arevei-engine-session-v1");

export async function saveUnlockedSession(blob: string): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: SESSION_AAD }, await wrappingKey(), new TextEncoder().encode(blob));
  await idb("readwrite", (s) => s.put({ iv, ct }, "engine-session"));
}

export async function loadUnlockedSession(): Promise<string | null> {
  const rec = await idb<{ iv: Uint8Array; ct: ArrayBuffer } | undefined>("readonly", (s) => s.get("engine-session"));
  if (!rec) return null;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv, additionalData: SESSION_AAD }, await wrappingKey(), rec.ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

export async function forgetUnlockedSession(): Promise<void> {
  await idb("readwrite", (s) => s.delete("engine-session"));
}
