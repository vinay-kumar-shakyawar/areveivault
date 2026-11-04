import { useCallback, useEffect, useState } from "react";
import { Building2, Copy, FolderKanban, Pencil, Plus, ShieldCheck, Trash2, UserMinus, Users } from "lucide-react";
import type { ItemSummary, VaultSummary } from "@arevei/client";
import { Avatar, Badge, Button, Field, IconButton, Input, Modal, Select, Status, Toggle } from "@arevei/ui";
import { api, copyText, engine, errorMessage, refresh, useApp } from "../lib/app";
import { approveMember, changeRole, offboard, rotateVault, type OffboardReport } from "../lib/admin";
import { useEngine } from "../lib/hooks";
import type { AdminTab } from "../lib/nav";
import { toast } from "../lib/toast";

interface Member {
  user_id: string;
  email: string;
  role: string;
  status: string;
  public_keys: { x25519: string; ed25519: string };
  cert: unknown | null;
}

const useMembers = (): Member[] => useApp().sync?.members ?? [];

export function AdminScreen({ tab }: { tab: AdminTab }) {
  return (
    <div className="mx-auto max-w-[920px] p-5 sm:p-6">
      {tab === "members" ? <MembersTab /> : tab === "invites" ? <InvitesTab /> : tab === "projects" ? <ProjectsTab /> : <AuditTab />}
    </div>
  );
}

async function attempt(fn: () => Promise<unknown>, ok?: string): Promise<boolean> {
  try {
    await fn();
    if (ok) toast.success(ok);
    return true;
  } catch (e) {
    toast.error(errorMessage(e));
    return false;
  }
}

// ------------------------------------------------------------------ members
function MembersTab() {
  const members = useMembers();
  const { session } = useApp();
  const [approving, setApproving] = useState<Member | null>(null);
  const [offboarding, setOffboarding] = useState<Member | null>(null);
  const [report, setReport] = useState<OffboardReport | null>(null);
  const pending = members.filter((m) => m.status === "pending_approval");
  const active = members.filter((m) => m.status !== "pending_approval");
  const isOwner = session?.role === "owner";
  useEffect(() => {
    void refresh().catch(() => undefined);
  }, []);

  return (
    <div className="space-y-5">
      {pending.length ? (
        <section className="av-card overflow-hidden" data-testid="pending-members">
          <h3 className="border-b border-line px-4 py-3 text-[14px] font-semibold">Waiting for approval</h3>
          {pending.map((m) => (
            <div key={m.user_id} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
              <Avatar name={m.email} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[14px]">{m.email}</div>
                <div className="text-[12px] text-muted">Invited as {m.role}</div>
              </div>
              <Button size="sm" variant="primary" onClick={() => setApproving(m)} data-testid={`approve-${m.email}`}>
                Verify & approve
              </Button>
            </div>
          ))}
        </section>
      ) : null}

      <section className="av-card overflow-hidden">
        <h3 className="flex items-center gap-2 border-b border-line px-4 py-3 text-[14px] font-semibold">
          <Users className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Members ({active.length})
        </h3>
        {active.map((m) => {
          const self = m.user_id === session?.user_id;
          return (
            <div key={m.user_id} className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
              <Avatar name={m.email} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[14px]">
                  {m.email} {self ? <span className="text-muted">(you)</span> : null}
                </div>
                <div className="text-[12px]">
                  {m.status === "disabled" ? <Status tone="neutral">Disabled</Status> : m.cert ? <Status tone="success">Verified</Status> : <Status tone="warning">No certificate</Status>}
                </div>
              </div>
              <Select
                className="w-32"
                aria-label={`Role for ${m.email}`}
                value={m.role}
                disabled={self || m.status === "disabled" || (!isOwner && (m.role === "owner" || m.role === "admin"))}
                onChange={(e) => void attempt(() => changeRole(m, e.target.value), "Role updated")}
              >
                <option value="member">Member</option>
                <option value="admin" disabled={!isOwner}>
                  Admin
                </option>
                <option value="owner" disabled={!isOwner}>
                  Owner
                </option>
              </Select>
              {!self && m.status !== "disabled" ? (
                <IconButton label={`Offboard ${m.email}`} onClick={() => setOffboarding(m)}>
                  <UserMinus aria-hidden />
                </IconButton>
              ) : null}
            </div>
          );
        })}
      </section>

      <ApproveModal member={approving} onClose={() => setApproving(null)} />

      <Modal
        open={!!offboarding}
        onClose={() => setOffboarding(null)}
        title="Offboard member"
        footer={
          <>
            <Button onClick={() => setOffboarding(null)}>Cancel</Button>
            <Button
              variant="danger"
              onClick={() => {
                const m = offboarding!;
                setOffboarding(null);
                void attempt(async () => setReport(await offboard(m)));
              }}
            >
              Offboard {offboarding?.email}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-[13px]">
          <p>This immediately disables the account, signs out every device, and removes access to all projects. Every affected project's key is then rotated.</p>
          <p className="text-muted">
            They may have copied anything they could see. After offboarding you'll get a list of credentials to change at the source services — that's the only real revocation.
          </p>
        </div>
      </Modal>

      <Modal open={!!report} onClose={() => setReport(null)} title={`Offboarding report: ${report?.email ?? ""}`} wide>
        {report ? (
          <div className="space-y-4" data-testid="offboard-report">
            <Status tone={report.failed.length ? "warning" : "success"}>
              {report.rotated.length} project key{report.rotated.length === 1 ? "" : "s"} rotated
              {report.failed.length ? `, ${report.failed.length} failed — retry from Clients & projects` : ""}
            </Status>
            <p className="text-[13px] text-muted">Change these credentials at each service ({report.credentials.length}):</p>
            <ul className="max-h-[50vh] divide-y divide-[var(--border)] overflow-auto rounded-sm border border-line">
              {report.credentials.map((c) => (
                <li key={c.id} className="flex items-center gap-3 px-3 py-2 text-[13px]">
                  <span className="min-w-0 flex-1 truncate">
                    {c.title} <span className="text-muted">· {c.subtitle}</span>
                  </span>
                  <span className="truncate text-[12px] text-muted">{c.vault_name}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

function ApproveModal({ member, onClose }: { member: Member | null; onClose: () => void }) {
  const [fp, setFp] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setConfirmed(false);
    if (member) void engine.call<{ fingerprint: string }>("fingerprint", { public_key: member.public_keys.ed25519 }).then((r) => setFp(r.fingerprint));
  }, [member]);
  return (
    <Modal
      open={!!member}
      onClose={onClose}
      title="Verify new member"
      testId="approve-modal"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!confirmed}
            loading={busy}
            data-testid="approve-confirm"
            onClick={async () => {
              setBusy(true);
              if (await attempt(() => approveMember(member!), "Member approved")) onClose();
              setBusy(false);
            }}
          >
            Approve
          </Button>
        </>
      }
    >
      {member ? (
        <div className="space-y-4 text-[13px]">
          <p>
            Ask <strong>{member.email}</strong> to read the fingerprint shown on their screen, by phone or in person. Approve only if it matches exactly. This protects against a compromised server
            substituting its own key.
          </p>
          <div className="rounded border border-line bg-bg p-4 text-center font-mono text-[15px] tracking-wider" data-testid="approve-fingerprint">
            {fp}
          </div>
          <label className="flex items-start gap-2">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-0.5" data-testid="approve-checkbox" />
            The fingerprint matches what {member.email} sees.
          </label>
        </div>
      ) : null}
    </Modal>
  );
}

// ------------------------------------------------------------------ invites
function InvitesTab() {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [link, setLink] = useState<string | null>(null);
  const [invites, setInvites] = useState<any[]>([]);
  const load = useCallback(() => void api.invites().then(setInvites).catch(() => setInvites([])), []);
  useEffect(load, [load]);

  return (
    <div className="space-y-5">
      <section className="av-card p-5">
        <h3 className="text-[14px] font-semibold">Invite a team member</h3>
        <p className="mt-1 text-[13px] text-muted">Invites expire after 7 days and work once. Send the link through a channel you trust. New members need your approval after signing up.</p>
        <form
          className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            void attempt(async () => {
              const r = await api.createInvite(email.trim().toLowerCase(), role);
              setLink(`${location.origin}/signup?invite=${encodeURIComponent(r.invite_token)}`);
              setEmail("");
              load();
            });
          }}
        >
          <div className="flex-1">
            <Field label="Email" htmlFor="inv-email">
              <Input id="inv-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} data-testid="invite-email" />
            </Field>
          </div>
          <Field label="Role" htmlFor="inv-role">
            <Select id="inv-role" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </Select>
          </Field>
          <Button type="submit" variant="primary" data-testid="invite-create">
            <Plus aria-hidden /> Create invite
          </Button>
        </form>
        {link ? (
          <div className="mt-4 flex items-center gap-2 rounded-sm border border-line bg-bg px-3 py-2">
            <code className="min-w-0 flex-1 truncate font-mono text-[12px]" data-testid="invite-link">
              {link}
            </code>
            <IconButton label="Copy invite link" onClick={() => void copyText(link, "Invite link")}>
              <Copy aria-hidden />
            </IconButton>
          </div>
        ) : null}
      </section>
      <section className="av-card overflow-hidden">
        <h3 className="border-b border-line px-4 py-3 text-[14px] font-semibold">Open invites</h3>
        {invites.length === 0 ? <div className="px-4 py-3 text-[13px] text-muted">None.</div> : null}
        {invites.map((inv) => {
          const id = inv.id ?? inv.token_id;
          return (
            <div key={id} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
              <div className="min-w-0 flex-1">
                <div className="truncate text-[14px]">{inv.email}</div>
                <div className="text-[12px] text-muted">
                  {inv.role} · expires {inv.expires_at ? new Date(inv.expires_at * 1000).toLocaleDateString() : "—"}
                  {inv.used_at ? " · used" : ""}
                </div>
              </div>
              <IconButton label={`Revoke invite for ${inv.email}`} onClick={() => void attempt(async () => (await api.deleteInvite(id), load()), "Invite revoked")}>
                <Trash2 aria-hidden />
              </IconButton>
            </div>
          );
        })}
      </section>
    </div>
  );
}

// ------------------------------------------------------------------ clients & projects
function ProjectsTab() {
  const { data } = useEngine<{ vaults: VaultSummary[]; clients: { id: string; name: string }[] }>("list_vaults", {});
  const [clientName, setClientName] = useState("");
  const [projectFor, setProjectFor] = useState<string | null>(null);
  const [projectName, setProjectName] = useState("");
  const [rename, setRename] = useState<{ kind: "client" | "vault"; id: string; name: string } | null>(null);
  const [membersOf, setMembersOf] = useState<VaultSummary | null>(null);
  const projects = (data?.vaults ?? []).filter((v) => v.kind === "project");

  const createClient = () =>
    attempt(async () => {
      const r = await engine.call<{ id: string; name_enc: string }>("create_client", { name: clientName.trim() });
      await api.createClient(r);
      setClientName("");
      await refresh();
    }, "Client created");

  const createProject = () =>
    attempt(async () => {
      const req = await engine.call("create_vault", { name: projectName.trim(), client_id: projectFor });
      await api.createVault(req);
      setProjectFor(null);
      setProjectName("");
      await refresh(true);
    }, "Project created");

  const doRename = () =>
    attempt(async () => {
      if (!rename) return;
      if (rename.kind === "client") {
        const r = await engine.call<{ name_enc: string }>("create_client", { client_id: rename.id, name: rename.name.trim() });
        await api.updateClient(rename.id, r.name_enc);
      } else {
        const r = await engine.call<{ name_enc: string }>("encrypt_vault_name", { vault_id: rename.id, name: rename.name.trim() });
        await api.updateVault(rename.id, r.name_enc);
      }
      setRename(null);
      await refresh(true);
    }, "Renamed");

  return (
    <div className="space-y-5">
      <section className="av-card p-5">
        <h3 className="text-[14px] font-semibold">New client</h3>
        <form
          className="mt-3 flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (clientName.trim()) void createClient();
          }}
        >
          <Input placeholder="Client name, e.g. Acme Corp" value={clientName} onChange={(e) => setClientName(e.target.value)} aria-label="Client name" data-testid="client-name" />
          <Button type="submit" variant="primary" data-testid="client-create">
            <Plus aria-hidden /> Add
          </Button>
        </form>
        <p className="mt-2 text-[12px] text-muted">Client and project names are encrypted. The server only sees opaque IDs.</p>
      </section>

      {(data?.clients ?? []).map((c) => {
        const list = projects.filter((p) => p.client_id === c.id);
        return (
          <section key={c.id} className="av-card overflow-hidden" data-testid={`client-${c.name}`}>
            <div className="flex items-center gap-2 border-b border-line px-4 py-3">
              <Building2 className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden />
              <h3 className="flex-1 truncate text-[14px] font-semibold">{c.name}</h3>
              <IconButton label={`Rename ${c.name}`} onClick={() => setRename({ kind: "client", id: c.id, name: c.name })}>
                <Pencil aria-hidden />
              </IconButton>
              {list.length === 0 ? (
                <IconButton label={`Delete ${c.name}`} onClick={() => void attempt(async () => (await api.deleteClient(c.id), await refresh()), "Client deleted")}>
                  <Trash2 aria-hidden />
                </IconButton>
              ) : null}
              <Button size="sm" onClick={() => setProjectFor(c.id)} data-testid={`project-add-${c.name}`}>
                <Plus aria-hidden /> Project
              </Button>
            </div>
            {list.length === 0 ? <div className="px-4 py-3 text-[13px] text-muted">No projects yet.</div> : null}
            {list.map((p) => (
              <div key={p.id} className="flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-b-0">
                <FolderKanban className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
                <span className="min-w-0 flex-1 truncate text-[13px]">
                  {p.name} <span className="text-muted">· {p.item_count} items · key v{p.key_version}</span>
                </span>
                <Button size="sm" onClick={() => setMembersOf(p)} data-testid={`project-members-${p.name}`}>
                  <Users aria-hidden /> Access
                </Button>
                <IconButton label={`Rename ${p.name}`} onClick={() => setRename({ kind: "vault", id: p.id, name: p.name })}>
                  <Pencil aria-hidden />
                </IconButton>
                <IconButton
                  label={`Delete ${p.name}`}
                  onClick={() => {
                    if (confirm(`Delete project "${p.name}"? Its items move to Trash first.`)) void attempt(async () => (await api.deleteVault(p.id), await refresh(true)), "Project deleted");
                  }}
                >
                  <Trash2 aria-hidden />
                </IconButton>
              </div>
            ))}
          </section>
        );
      })}

      <Modal
        open={projectFor !== null}
        onClose={() => setProjectFor(null)}
        title="New project"
        footer={
          <Button variant="primary" disabled={!projectName.trim()} onClick={() => void createProject()} data-testid="project-create">
            Create project
          </Button>
        }
      >
        <Field label="Project name" htmlFor="proj-name">
          <Input id="proj-name" autoFocus value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="e.g. Website redesign" data-testid="project-name" />
        </Field>
      </Modal>

      <Modal open={!!rename} onClose={() => setRename(null)} title="Rename" footer={<Button variant="primary" onClick={() => void doRename()}>Save</Button>}>
        {rename ? <Input autoFocus aria-label="New name" value={rename.name} onChange={(e) => setRename({ ...rename, name: e.target.value })} /> : null}
      </Modal>

      {membersOf ? <ProjectAccess vault={membersOf} onClose={() => setMembersOf(null)} /> : null}
    </div>
  );
}

function ProjectAccess({ vault, onClose }: { vault: VaultSummary; onClose: () => void }) {
  const members = useMembers();
  const [list, setList] = useState<{ user_id: string; role: string; copy_only: boolean }[]>([]);
  const [addUser, setAddUser] = useState("");
  const [addRole, setAddRole] = useState("member");
  const [addCopyOnly, setAddCopyOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => void api.vaultMembers(vault.id).then(setList).catch((e) => toast.error(errorMessage(e))), [vault.id]);
  useEffect(load, [load]);

  const email = (id: string) => members.find((m) => m.user_id === id)?.email ?? id;
  const candidates = members.filter((m) => m.status === "active" && m.cert && !list.some((l) => l.user_id === m.user_id));

  const add = () =>
    attempt(async () => {
      setBusy(true);
      try {
        const grant = await engine.call("grant_vault", { vault_id: vault.id, user_id: addUser });
        await api.putVaultMember(vault.id, addUser, { role: addRole, copy_only: addCopyOnly, grant });
        setAddUser("");
        load();
        await refresh();
      } finally {
        setBusy(false);
      }
    }, "Access granted");

  const update = (uid: string, role: string, copy_only: boolean) =>
    attempt(async () => {
      await api.putVaultMember(vault.id, uid, { role, copy_only, grant: null });
      load();
    }, "Updated");

  const remove = (uid: string) =>
    attempt(async () => {
      setBusy(true);
      try {
        await api.removeVaultMember(vault.id, uid);
        await refresh(true);
        await rotateVault(vault.id);
        await refresh(true);
        load();
      } finally {
        setBusy(false);
      }
    }, "Access removed and project key rotated. Change any credentials they could see at the source.");

  return (
    <Modal open onClose={onClose} title={`Access: ${vault.client_name ? `${vault.client_name} / ` : ""}${vault.name}`} wide testId="project-access">
      <div className="space-y-5">
        <div className="space-y-2">
          {list.length === 0 ? <div className="text-[13px] text-muted">Only administrators can access this project.</div> : null}
          {list.map((m) => (
            <div key={m.user_id} className="flex flex-wrap items-center gap-3 rounded-sm border border-line px-3 py-2">
              <Avatar name={email(m.user_id)} size={28} />
              <span className="min-w-0 flex-1 truncate text-[13px]">{email(m.user_id)}</span>
              <Select className="w-36" aria-label="Project role" value={m.role} onChange={(e) => void update(m.user_id, e.target.value, m.copy_only)}>
                <option value="manager">Manager</option>
                <option value="member">Member</option>
                <option value="read_only">Read-only</option>
              </Select>
              <span className="flex items-center gap-2 text-[12px] text-muted">
                Copy only
                <Toggle checked={m.copy_only} onChange={(v) => void update(m.user_id, m.role, v)} label={`Copy only for ${email(m.user_id)}`} />
              </span>
              <IconButton label={`Remove ${email(m.user_id)}`} disabled={busy} onClick={() => void remove(m.user_id)}>
                <UserMinus aria-hidden />
              </IconButton>
            </div>
          ))}
        </div>
        <div className="rounded-sm border border-line p-3">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-medium">
            <ShieldCheck className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Add a verified member
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <Select className="min-w-[200px] flex-1" aria-label="Member" value={addUser} onChange={(e) => setAddUser(e.target.value)} data-testid="access-user">
              <option value="">Choose…</option>
              {candidates.map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {m.email}
                </option>
              ))}
            </Select>
            <Select className="w-36" aria-label="Role" value={addRole} onChange={(e) => setAddRole(e.target.value)} data-testid="access-role">
              <option value="manager">Manager</option>
              <option value="member">Member</option>
              <option value="read_only">Read-only</option>
            </Select>
            <span className="flex items-center gap-2 text-[12px] text-muted">
              Copy only <Toggle checked={addCopyOnly} onChange={setAddCopyOnly} label="Copy only" />
            </span>
            <Button variant="primary" disabled={!addUser} loading={busy} onClick={() => void add()} data-testid="access-add">
              Grant access
            </Button>
          </div>
          <p className="mt-2 text-[12px] text-muted">
            The project key is encrypted to the member's certified public key. Read-only and copy-only are workflow guardrails, not cryptographic limits: anyone who can copy a secret can paste it elsewhere.
          </p>
        </div>
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------------ audit
function AuditTab() {
  const [rows, setRows] = useState<any[]>([]);
  const [titles, setTitles] = useState<Map<string, string>>(new Map());
  const [verify, setVerify] = useState<{ ok: boolean; count: number; head_hash: string; checkpoints?: any[] } | null>(null);
  const [more, setMore] = useState(true);

  const load = useCallback(async (before?: number) => {
    const page = await api.audit(before, 100);
    setRows((r) => (before ? [...r, ...page] : page));
    setMore(page.length === 100);
    const ids = [...new Set(page.filter((e: any) => e.target_type === "item").map((e: any) => e.target_id))];
    if (ids.length) {
      const [live, trash] = await Promise.all([
        engine.call<ItemSummary[]>("list_items", { ids }),
        engine.call<ItemSummary[]>("list_items", { ids, trash: true }),
      ]);
      setTitles((t) => new Map([...t, ...[...live, ...trash].map((i) => [i.id, i.title] as [string, string])]));
    }
  }, []);

  useEffect(() => {
    void load().catch((e) => toast.error(errorMessage(e)));
    void api.auditVerify().then(setVerify).catch(() => setVerify(null));
  }, [load]);

  return (
    <div className="space-y-5">
      <section className="av-card flex flex-wrap items-center gap-3 p-4">
        <div className="flex-1">
          <div className="text-[14px] font-semibold">Tamper-evident log</div>
          <div className="text-[12px] text-muted">Hash-chained entries with signed checkpoints. Item names are decrypted on your device only.</div>
        </div>
        {verify ? (
          verify.ok ? (
            <Status tone="success">Chain verified · {verify.count} entries</Status>
          ) : (
            <Status tone="danger">Chain verification FAILED</Status>
          )
        ) : (
          <Status tone="neutral">Verification unavailable</Status>
        )}
      </section>
      <section className="av-card overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-[12px]" data-testid="audit-table">
          <thead className="text-muted">
            <tr className="border-b border-line">
              <th className="px-3 py-2 font-medium">When</th>
              <th className="px-3 py-2 font-medium">Who</th>
              <th className="px-3 py-2 font-medium">Event</th>
              <th className="px-3 py-2 font-medium">Target</th>
              <th className="px-3 py-2 font-medium">IP / device</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className="border-b border-line last:border-b-0">
                <td className="whitespace-nowrap px-3 py-2 text-muted">{new Date(e.ts * 1000).toLocaleString()}</td>
                <td className="max-w-[180px] truncate px-3 py-2">{e.actor_email ?? e.actor_user_id ?? "—"}</td>
                <td className="px-3 py-2">
                  <Badge>{String(e.event_type).replace(/_/g, " ")}</Badge>
                </td>
                <td className="max-w-[220px] truncate px-3 py-2">{e.target_type === "item" ? titles.get(e.target_id) ?? <span className="text-muted">deleted item</span> : <span className="text-muted">{e.target_type}</span>}</td>
                <td className="max-w-[160px] truncate px-3 py-2 text-muted">{e.ip ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? <div className="px-4 py-6 text-center text-[13px] text-muted">No events.</div> : null}
      </section>
      {more && rows.length ? (
        <Button onClick={() => void load(rows[rows.length - 1].id)}>Load older</Button>
      ) : null}
    </div>
  );
}
