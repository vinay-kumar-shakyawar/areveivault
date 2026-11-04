/**
 * Minimal IndexedDB key-value store. Only ciphertext / non-secret values and
 * NON-EXTRACTABLE CryptoKeys are ever stored here — never decrypted vault data.
 */

const DB = "arevei-vault";
const STORE = "kv";

let dbPromise: Promise<IDBDatabase> | null = null;

function open(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbPromise;
}

function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(STORE, mode);
        const req = fn(t.objectStore(STORE));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      }),
  );
}

export const idb = {
  get: <T>(key: string) => tx<T | undefined>("readonly", (s) => s.get(key) as IDBRequest<T | undefined>).catch(() => undefined),
  set: (key: string, value: unknown) => tx("readwrite", (s) => s.put(value, key)).then(() => undefined),
  del: (key: string) => tx("readwrite", (s) => s.delete(key)).then(() => undefined),
};

/** Cached account info: email + the ENCRYPTED keyset (salt/KDF params inside). */
export interface CachedAccount {
  email: string;
  user_id: string;
  keyset: any;
}

export const accountStore = {
  get: () => idb.get<CachedAccount>("account"),
  set: (a: CachedAccount) => idb.set("account", a),
  clear: () => idb.del("account"),
};

/** TOFU pin of the organization signing key (packages/client PinStore). */
export const pinStore = {
  get: async (orgId: string) => (await idb.get<string>(`pin:${orgId}`)) ?? null,
  set: (orgId: string, pk: string) => idb.set(`pin:${orgId}`, pk),
};
