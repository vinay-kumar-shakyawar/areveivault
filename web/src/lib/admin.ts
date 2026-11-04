/** Admin operations composed from engine (crypto) + API (ciphertext) calls. */
import { nowSecs, type ItemSummary } from "@arevei/client";
import { api, engine, refresh } from "./app";

/** Re-key a project after membership shrank: new vault key, re-wrapped item keys, re-granted. */
export async function rotateVault(vaultId: string): Promise<void> {
  const members = await api.vaultMembers(vaultId);
  const req = await engine.call("rotate_vault", { vault_id: vaultId, member_ids: members.map((m) => m.user_id) });
  await api.rotateVault(vaultId, req);
}

export async function approveMember(m: { user_id: string; email: string; role: string; public_keys: unknown }): Promise<void> {
  const r = await engine.call<{ cert: unknown; grants: any[] }>("approve_member", {
    user_id: m.user_id,
    email: m.email,
    public_keys: m.public_keys,
    now: nowSecs(),
    admin: m.role === "admin" || m.role === "owner",
  });
  await api.approveMember(m.user_id, { cert: r.cert, grants: r.grants });
  await refresh(true);
}

export async function changeRole(m: { user_id: string; email: string; public_keys: unknown }, role: string): Promise<void> {
  let grants: any[] | undefined;
  if (role === "admin" || role === "owner") {
    const r = await engine.call<{ grants: any[] }>("approve_member", {
      user_id: m.user_id,
      email: m.email,
      public_keys: m.public_keys,
      now: nowSecs(),
      admin: true,
    });
    grants = r.grants.filter((g) => String(g.keyring_id).startsWith("org-admin:"));
  }
  await api.updateMember(m.user_id, { role, grants });
  await refresh(true);
}

export interface OffboardReport {
  email: string;
  rotated: string[];
  failed: { vaultId: string; error: string }[];
  credentials: (ItemSummary & { vault_name: string })[];
}

/** Disable the user, rotate every vault they could read, list credentials to rotate at the source. */
export async function offboard(m: { user_id: string; email: string }): Promise<OffboardReport> {
  const { affected_vault_ids } = await api.offboardMember(m.user_id);
  await refresh(true);
  const rotated: string[] = [];
  const failed: OffboardReport["failed"] = [];
  for (const vid of affected_vault_ids) {
    try {
      await rotateVault(vid);
      rotated.push(vid);
    } catch (e) {
      failed.push({ vaultId: vid, error: e instanceof Error ? e.message : String(e) });
    }
  }
  await refresh(true);
  const vaults = await engine.call<{ vaults: { id: string; name: string; client_name: string | null }[] }>("list_vaults");
  const names = new Map(vaults.vaults.map((v) => [v.id, v.client_name ? `${v.client_name} / ${v.name}` : v.name]));
  const credentials: OffboardReport["credentials"] = [];
  for (const vid of affected_vault_ids) {
    const items = await engine.call<ItemSummary[]>("list_items", { vault_id: vid });
    for (const it of items) credentials.push({ ...it, vault_name: names.get(vid) ?? vid });
  }
  return { email: m.email, rotated, failed, credentials };
}
