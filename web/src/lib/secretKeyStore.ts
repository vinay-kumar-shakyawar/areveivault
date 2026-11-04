/**
 * "Remember Secret Key on this device": the Secret Key is encrypted with a
 * NON-EXTRACTABLE WebCrypto AES-GCM key that lives in IndexedDB. Script can use
 * the key but can never read its raw bytes; on its own the Secret Key is useless
 * without the master password (architecture §6.3).
 */
import { idb } from "./idb";

const KEY = "sk-wrap-key";
const BLOB = "sk-wrapped";

async function wrappingKey(create: boolean): Promise<CryptoKey | null> {
  const existing = await idb.get<CryptoKey>(KEY);
  if (existing) return existing;
  if (!create) return null;
  const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idb.set(KEY, k);
  return k;
}

export const secretKeyStore = {
  async save(email: string, secretKey: string): Promise<void> {
    const key = (await wrappingKey(true))!;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(email) },
      key,
      new TextEncoder().encode(secretKey),
    );
    await idb.set(BLOB, { email, iv, ct: new Uint8Array(ct) });
  },

  async load(email: string): Promise<string | null> {
    const key = await wrappingKey(false);
    const blob = await idb.get<{ email: string; iv: Uint8Array; ct: Uint8Array }>(BLOB);
    if (!key || !blob || blob.email !== email) return null;
    try {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: blob.iv, additionalData: new TextEncoder().encode(email) },
        key,
        blob.ct,
      );
      return new TextDecoder().decode(pt);
    } catch {
      return null;
    }
  },

  async clear(): Promise<void> {
    await idb.del(BLOB);
    await idb.del(KEY);
  },
};
