import { useEffect, useState } from "react";
import {
  ArrowLeft,
  Check,
  Copy,
  ExternalLink,
  FolderInput,
  History,
  Paperclip,
  Pencil,
  RotateCcw,
  Star,
  Trash2,
  XCircle,
} from "lucide-react";
import type { ItemDetail as Detail, VaultSummary } from "@arevei/client";
import { Avatar, Badge, Button, IconButton, Modal, Select, Status } from "@arevei/ui";
import { TotpRow, ValueRow, type AuditCtx } from "../components/Secret";
import {
  api,
  audit,
  ConflictError,
  copyText,
  engine,
  errorMessage,
  moveItem,
  purgeItem,
  restoreItem,
  saveItem,
  toggleFavorite,
  trashItem,
  useApp,
} from "../lib/app";
import { downloadBytes } from "../lib/emergencyKit";
import { useEngine } from "../lib/hooks";
import { TYPES } from "../lib/itemTypes";
import { parseNotes, RichText } from "../lib/richtext";
import { toast } from "../lib/toast";

const fmt = (t: number | null | undefined) => (t ? new Date(t * 1000).toLocaleString() : "—");
const b64ToBytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const bytesToB64 = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
};
const safeUrl = (u: string) => {
  const withScheme = /^[a-z]+:\/\//i.test(u) ? u : `https://${u}`;
  return /^https?:\/\//i.test(withScheme) ? withScheme : null;
};

export function ItemDetail({ id, onEdit, onBack, onClosed }: { id: string; onEdit: () => void; onBack: () => void; onClosed: () => void }) {
  const { prefs } = useApp();
  const { data: d, error } = useEngine<Detail>("get_item", { id }, [id]);
  const { data: vaultList } = useEngine<{ vaults: VaultSummary[] }>("list_vaults", {});
  const [moveOpen, setMoveOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (d) audit.record("item_view", d.id, d.vault_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d?.id]);

  if (error) return <div className="p-6 text-[13px] text-muted">This item is no longer available.</div>;
  if (!d) return null;

  const it = d.item;
  const data = it.data;
  const T = TYPES[data.type] ?? TYPES.secure_note;
  const ctx: AuditCtx = { itemId: d.id, vaultId: d.vault_id };
  const vault = vaultList?.vaults.find((v) => v.id === d.vault_id);
  const readOnly = d.role === "read_only";
  const copyOnly = d.copy_only;
  const trashed = d.deleted_at !== null;
  const favorite = prefs.favorites.includes(d.id);

  const run = async (fn: () => Promise<void>, ok?: string) => {
    setBusy(true);
    try {
      await fn();
      if (ok) toast.success(ok);
    } catch (e) {
      toast.error(e instanceof ConflictError ? e.message : errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const toggleCode = (idx: number) =>
    run(async () => {
      const codes = [...(data.codes as any[])];
      const c = codes[idx];
      codes[idx] = { ...c, used: !c.used, used_at: !c.used ? Math.floor(Date.now() / 1000) : undefined };
      await saveItem(d.vault_id, { ...it, data: { ...data, codes } }, d.id);
    });

  const download = (att: { id: string; name: string; mime: string; file_key: string }) =>
    run(async () => {
      const ct = await api.getAttachment(att.id);
      const { data: plain } = await engine.call<{ data: string }>("decrypt_attachment", { attachment_id: att.id, file_key: att.file_key, ciphertext: bytesToB64(ct) });
      downloadBytes(b64ToBytes(plain), att.name, att.mime || "application/octet-stream");
      audit.record("item_copy", d.id, d.vault_id);
    });

  const writable = (vaultList?.vaults ?? []).filter((v) => v.unlocked && v.role !== "read_only" && v.id !== d.vault_id);

  return (
    <div className="flex h-full flex-col" data-testid="item-detail">
      <div className="flex h-14 items-center gap-2 border-b border-line px-3">
        <IconButton label="Back to list" className="lg:hidden" onClick={onBack}>
          <ArrowLeft aria-hidden />
        </IconButton>
        <div className="flex-1" />
        {!trashed ? (
          <>
            <IconButton label={favorite ? "Remove from favorites" : "Add to favorites"} active={favorite} onClick={() => void run(() => toggleFavorite(d.id))}>
              <Star aria-hidden fill={favorite ? "currentColor" : "none"} />
            </IconButton>
            {!readOnly ? (
              <>
                <IconButton label="Move to another vault" onClick={() => setMoveOpen(true)}>
                  <FolderInput aria-hidden />
                </IconButton>
                <IconButton label="Move to Trash" onClick={() => void run(async () => (await trashItem(d.id), onClosed()), "Moved to Trash")} data-testid="item-trash">
                  <Trash2 aria-hidden />
                </IconButton>
                <Button size="sm" onClick={onEdit} data-testid="item-edit">
                  <Pencil aria-hidden /> Edit
                </Button>
              </>
            ) : null}
          </>
        ) : !readOnly ? (
          <>
            <Button size="sm" onClick={() => void run(() => restoreItem(d.id), "Restored")} disabled={busy} data-testid="item-restore">
              <RotateCcw aria-hidden /> Restore
            </Button>
            <Button size="sm" variant="danger" onClick={() => void run(async () => (await purgeItem(d.id), onClosed()), "Deleted permanently")} disabled={busy} data-testid="item-purge">
              <XCircle aria-hidden /> Delete forever
            </Button>
          </>
        ) : null}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[720px] space-y-5 p-5 sm:p-6">
          <div className="flex items-start gap-4">
            <Avatar name={it.title} size={48} />
            <div className="min-w-0 flex-1">
              <h1 className="break-words text-xl font-semibold" data-testid="item-title">
                {it.title}
              </h1>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-muted">
                <span className="inline-flex items-center gap-1">
                  <T.icon className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden /> {T.label}
                </span>
                <span>·</span>
                <span>{vault ? (vault.client_name ? `${vault.client_name} / ${vault.name}` : vault.name) : ""}</span>
                {copyOnly ? <Badge>Copy only</Badge> : null}
                {readOnly ? <Badge>Read only</Badge> : null}
              </div>
            </div>
          </div>

          {trashed ? <Status tone="warning">In Trash since {fmt(d.deleted_at)}. Restore it to use it again.</Status> : null}

          <section className="av-card overflow-hidden">
            {T.fields.map((f) => {
              const raw = data[f.key];
              const value = raw === null || raw === undefined ? "" : String(raw);
              return (
                <ValueRow
                  key={f.key}
                  label={f.label}
                  value={value}
                  secret={f.kind === "secret" || f.kind === "secretarea"}
                  mono={f.mono}
                  multiline={f.kind === "textarea" || f.kind === "secretarea"}
                  copyOnly={copyOnly}
                  ctx={ctx}
                  testId={`field-${f.key}`}
                />
              );
            })}
            {data.type === "login" && data.totp ? <TotpRow ctx={ctx} /> : null}
            {data.type === "authenticator" && data.secret ? <TotpRow ctx={ctx} /> : null}
          </section>

          {data.type === "login" && Array.isArray(data.urls) && data.urls.some((u: any) => u.url) ? (
            <section className="av-card overflow-hidden">
              {data.urls
                .filter((u: any) => u.url)
                .map((u: any, i: number) => {
                  const href = safeUrl(u.url);
                  return (
                    <div key={i} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
                      <div className="min-w-0 flex-1">
                        <div className="text-[12px] text-muted">Website{u.match_mode && u.match_mode !== "domain" ? ` · match ${u.match_mode}` : ""}</div>
                        <div className="truncate text-[14px]">{u.url}</div>
                      </div>
                      {href ? (
                        <a className="av-icon-btn" href={href} target="_blank" rel="noopener noreferrer" aria-label={`Open ${u.url}`}>
                          <ExternalLink aria-hidden />
                        </a>
                      ) : null}
                    </div>
                  );
                })}
            </section>
          ) : null}

          {data.type === "recovery_codes" ? (
            <section className="av-card overflow-hidden">
              <div className="border-b border-line px-4 py-2 text-[12px] text-muted">
                {(data.codes as any[]).filter((c) => !c.used).length} of {(data.codes as any[]).length} codes unused
              </div>
              {(data.codes as any[]).map((c, i) => (
                <div key={i} className="flex items-center gap-3 border-b border-line px-4 py-2 last:border-b-0">
                  <span className={`flex-1 font-mono text-[13px] ${c.used ? "text-muted line-through" : ""}`}>{copyOnly && !c.used ? "••••••••" : c.code}</span>
                  {c.used ? <Badge>Used</Badge> : null}
                  {!c.used ? <ValueCopy value={c.code} ctx={ctx} /> : null}
                  {!readOnly ? (
                    <IconButton label={c.used ? "Mark unused" : "Mark used"} onClick={() => void toggleCode(i)} disabled={busy}>
                      {c.used ? <RotateCcw aria-hidden /> : <Check aria-hidden />}
                    </IconButton>
                  ) : null}
                </div>
              ))}
            </section>
          ) : null}

          {it.custom_fields && it.custom_fields.length ? (
            <section className="av-card overflow-hidden">
              {it.custom_fields.map((f, i) => (
                <ValueRow key={i} label={f.name || "Field"} value={f.value} secret={f.kind === "hidden"} copyOnly={copyOnly} ctx={ctx} />
              ))}
            </section>
          ) : null}

          {it.attachments && it.attachments.length ? (
            <section className="av-card overflow-hidden">
              {it.attachments.map((a) => (
                <div key={a.id} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
                  <Paperclip className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[14px]">{a.name}</div>
                    <div className="text-[12px] text-muted">{(a.size / 1024).toFixed(1)} KB</div>
                  </div>
                  <Button size="sm" onClick={() => void download(a)} disabled={busy}>
                    Download
                  </Button>
                </div>
              ))}
            </section>
          ) : null}

          {it.notes ? (
            <section className="av-card p-4">
              <div className="mb-2 text-[12px] text-muted">Notes</div>
              <RichText doc={parseNotes(it.notes)} />
            </section>
          ) : null}

          {it.tags && it.tags.length ? (
            <div className="flex flex-wrap gap-1.5">
              {it.tags.map((t) => (
                <Badge key={t}>#{t}</Badge>
              ))}
            </div>
          ) : null}

          {it.expires_at ? <ExpiryNote date={it.expires_at} /> : null}

          {it.password_history && it.password_history.length ? (
            <section>
              <button className="flex items-center gap-2 text-[13px] text-muted hover:text-fg" onClick={() => setHistoryOpen(!historyOpen)} aria-expanded={historyOpen}>
                <History className="h-4 w-4" strokeWidth={1.5} aria-hidden /> Password history ({it.password_history.length})
              </button>
              {historyOpen ? (
                <div className="av-card mt-2 overflow-hidden">
                  {it.password_history.map((h, i) => (
                    <ValueRow key={i} label={`Replaced ${fmt(h.replaced_at)}`} value={h.value} secret copyOnly={copyOnly} ctx={ctx} />
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}

          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-[12px] text-muted">
            <dt>Created</dt>
            <dd>
              {fmt(d.created_at)}
              {d.created_by ? ` by ${d.created_by}` : ""}
            </dd>
            <dt>Updated</dt>
            <dd>
              {fmt(d.updated_at)}
              {d.updated_by ? ` by ${d.updated_by}` : ""}
            </dd>
            <dt>Version</dt>
            <dd>{d.version}</dd>
          </dl>
        </div>
      </div>

      <Modal open={moveOpen} onClose={() => setMoveOpen(false)} title="Move item">
        <MoveForm
          vaults={writable}
          onMove={(to) =>
            void run(async () => {
              await moveItem(d.id, to);
              setMoveOpen(false);
            }, "Item moved")
          }
        />
      </Modal>
    </div>
  );
}

function ValueCopy({ value, ctx }: { value: string; ctx: AuditCtx }) {
  return (
    <IconButton label="Copy code" onClick={() => void copyText(value, "Recovery code", ctx)}>
      <Copy aria-hidden />
    </IconButton>
  );
}

function ExpiryNote({ date }: { date: string }) {
  const days = Math.round((new Date(date + "T00:00:00").getTime() - Date.now()) / 86_400_000);
  if (Number.isNaN(days)) return null;
  if (days < 0) return <Status tone="danger">Expired {-days} days ago ({date})</Status>;
  if (days <= 30) return <Status tone="warning">Expires in {days} days ({date})</Status>;
  return <Status tone="neutral">Expires {date}</Status>;
}

function MoveForm({ vaults, onMove }: { vaults: VaultSummary[]; onMove: (id: string) => void }) {
  const [to, setTo] = useState(vaults[0]?.id ?? "");
  if (!vaults.length) return <p className="text-[13px] text-muted">There are no other vaults you can write to.</p>;
  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">The item is re-encrypted with the destination vault's key. Members of the current vault lose access to it.</p>
      <Select value={to} onChange={(e) => setTo(e.target.value)} aria-label="Destination vault">
        {vaults.map((v) => (
          <option key={v.id} value={v.id}>
            {v.client_name ? `${v.client_name} / ${v.name}` : v.name}
          </option>
        ))}
      </Select>
      <Button variant="primary" block onClick={() => onMove(to)}>
        Move
      </Button>
    </div>
  );
}
