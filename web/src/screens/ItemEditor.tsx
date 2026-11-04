import { useEffect, useMemo, useRef, useState } from "react";
import { Bold, Code, Italic, List, Paperclip, Plus, Trash2, Wand2, X } from "lucide-react";
import type { Item, ItemDetail, ItemType, VaultSummary } from "@arevei/client";
import { Button, Field, IconButton, Input, Modal, Select, Textarea } from "@arevei/ui";
import { GeneratorPanel } from "../components/Generator";
import { QrImport } from "../components/QrImport";
import { api, ConflictError, engine, errorMessage, saveItem } from "../lib/app";
import { fileToB64, b64ToBytes } from "../lib/files";
import { emptyItem, TYPE_ORDER, TYPES, type FieldSpec } from "../lib/itemTypes";
import { markdownToNotes, notesToMarkdown } from "../lib/richtext";
import { toast } from "../lib/toast";

const MAX_FILE = 10 * 1024 * 1024;

export type EditorTarget = { mode: "new"; vaultId?: string; type?: ItemType } | { mode: "edit"; id: string };

interface PendingFile {
  id: string;
  file: File;
}

export function ItemEditor({ target, onClose, onSaved }: { target: EditorTarget; onClose: () => void; onSaved: (id: string) => void }) {
  const [vaults, setVaults] = useState<VaultSummary[]>([]);
  const [vaultId, setVaultId] = useState<string>("");
  const [item, setItem] = useState<Item | null>(null);
  const [itemId, setItemId] = useState<string | null>(null);
  const [notesMd, setNotesMd] = useState("");
  const [tagsText, setTagsText] = useState("");
  const [codesText, setCodesText] = useState("");
  const [pendingFiles, setPendingFiles] = useState<PendingFile[]>([]);
  const [removedAttachments, setRemovedAttachments] = useState<string[]>([]);
  const [generatorFor, setGeneratorFor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const notesRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void (async () => {
      const list = await engine.call<{ vaults: VaultSummary[] }>("list_vaults");
      const writable = list.vaults.filter((v) => v.unlocked && v.role !== "read_only");
      setVaults(writable);
      if (target.mode === "edit") {
        const d = await engine.call<ItemDetail>("get_item", { id: target.id });
        setItem(structuredClone(d.item));
        setItemId(d.id);
        setVaultId(d.vault_id);
        setNotesMd(notesToMarkdown(d.item.notes));
        setTagsText((d.item.tags ?? []).join(", "));
        if (d.item.data.type === "recovery_codes") setCodesText((d.item.data.codes as any[]).map((c) => c.code).join("\n"));
      } else {
        const t = target.type ?? "login";
        setItem(emptyItem(t) as Item);
        const preferred = writable.find((v) => v.id === target.vaultId) ?? writable.find((v) => v.kind === "personal") ?? writable[0];
        setVaultId(preferred?.id ?? "");
      }
    })().catch((e) => setError(errorMessage(e)));
  }, [target]);

  const T = item ? TYPES[item.data.type] : null;
  const setData = (patch: Record<string, unknown>) => setItem((it) => (it ? { ...it, data: { ...it.data, ...patch } } : it));
  const changeType = (t: ItemType) => {
    const fresh = emptyItem(t) as Item;
    setItem((it) => (it ? { ...fresh, title: it.title, notes: it.notes, tags: it.tags, custom_fields: it.custom_fields } : fresh));
  };

  const wrap = (before: string, after = before) => {
    const ta = notesRef.current;
    if (!ta) return;
    const { selectionStart: s, selectionEnd: e } = ta;
    const next = notesMd.slice(0, s) + before + notesMd.slice(s, e) + after + notesMd.slice(e);
    setNotesMd(next);
    requestAnimationFrame(() => {
      ta.focus();
      ta.setSelectionRange(s + before.length, e + before.length);
    });
  };

  const save = async () => {
    if (!item || !T) return;
    setError(null);
    if (!item.title.trim()) return setError("Title is required.");
    if (!vaultId) return setError("Choose a vault.");
    setBusy(true);
    try {
      const out: Item = {
        ...item,
        title: item.title.trim(),
        notes: markdownToNotes(notesMd),
        tags: tagsText
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        custom_fields: (item.custom_fields ?? []).filter((f) => f.name || f.value),
        expires_at: item.expires_at || null,
        attachments: (item.attachments ?? []).filter((a) => !removedAttachments.includes(a.id)),
      };
      if (out.data.type === "login") {
        out.data = { ...out.data, urls: (out.data.urls as any[]).filter((u) => u.url?.trim()), totp: out.data.totp?.trim() || null };
      }
      if (out.data.type === "recovery_codes") {
        const prev = new Map(((item.data.codes as any[]) ?? []).map((c) => [c.code, c]));
        out.data = {
          ...out.data,
          codes: codesText
            .split(/\r?\n/)
            .map((c) => c.trim())
            .filter(Boolean)
            .map((code) => prev.get(code) ?? { code, used: false }),
        };
      }
      if (out.data.type === "server") out.data = { ...out.data, port: out.data.port ? Number(out.data.port) : null };
      if (out.data.type === "authenticator") out.data = { ...out.data, digits: Number(out.data.digits), period: Number(out.data.period) };

      const uploadAll = async (forId: string) => {
        const refs = [];
        for (const pf of pendingFiles) {
          const enc = await engine.call<{ file_key: string; ciphertext: string }>("encrypt_attachment", { attachment_id: pf.id, data: await fileToB64(pf.file) });
          await api.putAttachment(pf.id, forId, b64ToBytes(enc.ciphertext));
          refs.push({ id: pf.id, name: pf.file.name, mime: pf.file.type || "application/octet-stream", size: pf.file.size, file_key: enc.file_key });
        }
        return refs;
      };

      let savedId: string;
      if (itemId) {
        const refs = await uploadAll(itemId);
        savedId = await saveItem(vaultId, { ...out, attachments: [...(out.attachments ?? []), ...refs] }, itemId);
      } else {
        const newId = crypto.randomUUID();
        savedId = await saveItem(vaultId, out, null, newId);
        if (pendingFiles.length) {
          const refs = await uploadAll(savedId);
          await saveItem(vaultId, { ...out, attachments: refs }, savedId);
        }
      }
      for (const id of removedAttachments) await api.deleteAttachment(id).catch(() => undefined);
      toast.success("Saved");
      onSaved(savedId);
    } catch (e) {
      setError(e instanceof ConflictError ? e.message : errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const renderField = (f: FieldSpec) => {
    if (!item) return null;
    const v = item.data[f.key] ?? "";
    const id = `f-${f.key}`;
    let control;
    if (f.kind === "select") {
      control = (
        <Select id={id} value={String(v)} onChange={(e) => setData({ [f.key]: e.target.value })} data-testid={`edit-${f.key}`}>
          {f.options!.map((o) => (
            <option key={o} value={o}>
              {o || "—"}
            </option>
          ))}
        </Select>
      );
    } else if (f.kind === "textarea" || f.kind === "secretarea") {
      control = <Textarea id={id} mono={f.mono} rows={4} value={String(v)} onChange={(e) => setData({ [f.key]: e.target.value })} spellCheck={false} data-testid={`edit-${f.key}`} />;
    } else {
      control = (
        <div className="av-input-group">
          <Input
            id={id}
            type={f.kind === "number" ? "number" : "text"}
            mono={f.mono || f.kind === "secret"}
            autoComplete="off"
            spellCheck={false}
            placeholder={f.placeholder}
            value={String(v ?? "")}
            onChange={(e) => setData({ [f.key]: e.target.value })}
            data-testid={`edit-${f.key}`}
          />
          {f.generator ? (
            <IconButton label="Generate password" className="h-9 w-9 border border-line-input" onClick={() => setGeneratorFor(f.key)} data-testid={`generate-${f.key}`}>
              <Wand2 aria-hidden />
            </IconButton>
          ) : null}
        </div>
      );
    }
    return (
      <Field key={f.key} label={f.label} htmlFor={id}>
        {control}
      </Field>
    );
  };

  const title = target.mode === "edit" ? "Edit item" : "New item";
  const typeOptions = useMemo(() => TYPE_ORDER.map((t) => ({ t, ...TYPES[t] })), []);

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      wide
      testId="item-editor"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={() => void save()} loading={busy} disabled={!item} data-testid="item-save">
            Save
          </Button>
        </>
      }
    >
      {!item || !T ? (
        error ? <div className="text-danger">{error}</div> : null
      ) : (
        <div className="space-y-5">
          {target.mode === "new" ? (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4" role="radiogroup" aria-label="Item type">
              {typeOptions.map(({ t, label, icon: Icon }) => (
                <button
                  key={t}
                  role="radio"
                  aria-checked={item.data.type === t}
                  onClick={() => changeType(t)}
                  className={`flex items-center gap-2 rounded-sm border px-3 py-2 text-left text-[12px] transition-colors ${item.data.type === t ? "border-silver-strong bg-raised text-fg" : "border-line text-muted hover:text-fg"}`}
                  data-testid={`type-${t}`}
                >
                  <Icon className="h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden />
                  <span className="truncate">{label}</span>
                </button>
              ))}
            </div>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Title" htmlFor="f-title">
              <Input id="f-title" autoFocus value={item.title} onChange={(e) => setItem({ ...item, title: e.target.value })} data-testid="edit-title" />
            </Field>
            <Field label="Vault" htmlFor="f-vault" hint={target.mode === "edit" ? "Use Move to change vaults." : undefined}>
              <Select id="f-vault" value={vaultId} disabled={target.mode === "edit"} onChange={(e) => setVaultId(e.target.value)} data-testid="edit-vault">
                {vaults.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.client_name ? `${v.client_name} / ${v.name}` : v.name}
                  </option>
                ))}
              </Select>
            </Field>
          </div>

          {T.fields.length ? <div className="grid gap-4 sm:grid-cols-2">{T.fields.map(renderField)}</div> : null}

          {item.data.type === "login" ? (
            <>
              <div className="space-y-2">
                <div className="av-label">Websites</div>
                {(item.data.urls as any[]).map((u, i) => (
                  <div key={i} className="flex gap-2">
                    <Input
                      placeholder="https://example.com/login"
                      value={u.url}
                      onChange={(e) => {
                        const urls = [...(item.data.urls as any[])];
                        urls[i] = { ...u, url: e.target.value };
                        setData({ urls });
                      }}
                      aria-label={`Website ${i + 1}`}
                      data-testid={`edit-url-${i}`}
                    />
                    <Select
                      className="w-40"
                      value={u.match_mode ?? "domain"}
                      aria-label="Match rule"
                      onChange={(e) => {
                        const urls = [...(item.data.urls as any[])];
                        urls[i] = { ...u, match_mode: e.target.value };
                        setData({ urls });
                      }}
                    >
                      <option value="domain">Same domain</option>
                      <option value="host">Exact host</option>
                      <option value="exact">URL prefix</option>
                      <option value="never">Never autofill</option>
                    </Select>
                    <IconButton label="Remove website" onClick={() => setData({ urls: (item.data.urls as any[]).filter((_, j) => j !== i) })}>
                      <X aria-hidden />
                    </IconButton>
                  </div>
                ))}
                <Button size="sm" onClick={() => setData({ urls: [...(item.data.urls as any[]), { url: "", match_mode: "domain" }] })}>
                  <Plus aria-hidden /> Add website
                </Button>
              </div>
              <div className="space-y-2">
                <Field label="Two-factor secret (optional)" htmlFor="f-totp" hint="Base32 secret or otpauth:// URI. The code is generated on your device.">
                  <Input id="f-totp" mono autoComplete="off" spellCheck={false} value={item.data.totp ?? ""} onChange={(e) => setData({ totp: e.target.value })} data-testid="edit-totp" />
                </Field>
                <QrImport onParsed={(_p, uri) => setData({ totp: uri })} />
              </div>
            </>
          ) : null}

          {item.data.type === "authenticator" ? (
            <QrImport
              onParsed={(p) => {
                setData({ issuer: p.issuer, account: p.account, secret: p.secret, algorithm: p.algorithm, digits: p.digits, period: p.period });
                if (!item.title) setItem((it) => (it ? { ...it, title: p.issuer || p.account } : it));
              }}
            />
          ) : null}

          {item.data.type === "recovery_codes" ? (
            <Field label="Codes (one per line)" htmlFor="f-codes">
              <Textarea id="f-codes" mono rows={8} value={codesText} onChange={(e) => setCodesText(e.target.value)} spellCheck={false} data-testid="edit-codes" />
            </Field>
          ) : null}

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="av-label" htmlFor="f-notes">
                Notes
              </label>
              <div className="flex gap-0.5">
                <IconButton label="Bold" onClick={() => wrap("**")}>
                  <Bold aria-hidden />
                </IconButton>
                <IconButton label="Italic" onClick={() => wrap("*")}>
                  <Italic aria-hidden />
                </IconButton>
                <IconButton label="Inline code" onClick={() => wrap("`")}>
                  <Code aria-hidden />
                </IconButton>
                <IconButton label="List item" onClick={() => wrap("\n- ", "")}>
                  <List aria-hidden />
                </IconButton>
              </div>
            </div>
            <Textarea id="f-notes" ref={notesRef} rows={item.data.type === "secure_note" ? 10 : 4} value={notesMd} onChange={(e) => setNotesMd(e.target.value)} data-testid="edit-notes" />
            <div className="av-hint">Supports **bold**, *italic*, `code`, lists (- item), headings (# title), and [links](https://…).</div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Tags" htmlFor="f-tags" hint="Comma separated">
              <Input id="f-tags" value={tagsText} onChange={(e) => setTagsText(e.target.value)} data-testid="edit-tags" />
            </Field>
            <Field label="Expiry reminder" htmlFor="f-exp" hint="Shown on the Security page. Never sent to the server in plaintext.">
              <Input id="f-exp" type="date" value={item.expires_at ?? ""} onChange={(e) => setItem({ ...item, expires_at: e.target.value || null })} />
            </Field>
          </div>

          <div className="space-y-2">
            <div className="av-label">Custom fields</div>
            {(item.custom_fields ?? []).map((f, i) => (
              <div key={i} className="flex gap-2">
                <Input
                  className="w-40"
                  placeholder="Name"
                  value={f.name}
                  onChange={(e) => {
                    const cf = [...item.custom_fields!];
                    cf[i] = { ...f, name: e.target.value };
                    setItem({ ...item, custom_fields: cf });
                  }}
                  aria-label="Field name"
                />
                <Input
                  type={f.kind === "date" ? "date" : "text"}
                  mono={f.kind === "hidden"}
                  placeholder="Value"
                  value={f.value}
                  onChange={(e) => {
                    const cf = [...item.custom_fields!];
                    cf[i] = { ...f, value: e.target.value };
                    setItem({ ...item, custom_fields: cf });
                  }}
                  aria-label="Field value"
                />
                <Select
                  className="w-28"
                  value={f.kind}
                  aria-label="Field type"
                  onChange={(e) => {
                    const cf = [...item.custom_fields!];
                    cf[i] = { ...f, kind: e.target.value as any };
                    setItem({ ...item, custom_fields: cf });
                  }}
                >
                  <option value="text">Text</option>
                  <option value="hidden">Hidden</option>
                  <option value="url">URL</option>
                  <option value="date">Date</option>
                </Select>
                <IconButton label="Remove field" onClick={() => setItem({ ...item, custom_fields: item.custom_fields!.filter((_, j) => j !== i) })}>
                  <Trash2 aria-hidden />
                </IconButton>
              </div>
            ))}
            <Button size="sm" onClick={() => setItem({ ...item, custom_fields: [...(item.custom_fields ?? []), { name: "", value: "", kind: "text" }] })}>
              <Plus aria-hidden /> Add field
            </Button>
          </div>

          <div className="space-y-2">
            <div className="av-label">Attachments (encrypted, max 10 MB each)</div>
            {(item.attachments ?? [])
              .filter((a) => !removedAttachments.includes(a.id))
              .map((a) => (
                <div key={a.id} className="flex items-center gap-2 text-[13px]">
                  <Paperclip className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
                  <span className="flex-1 truncate">{a.name}</span>
                  <IconButton label={`Remove ${a.name}`} onClick={() => setRemovedAttachments([...removedAttachments, a.id])}>
                    <X aria-hidden />
                  </IconButton>
                </div>
              ))}
            {pendingFiles.map((p) => (
              <div key={p.id} className="flex items-center gap-2 text-[13px]">
                <Paperclip className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden />
                <span className="flex-1 truncate">{p.file.name} (will upload on save)</span>
                <IconButton label={`Remove ${p.file.name}`} onClick={() => setPendingFiles(pendingFiles.filter((x) => x.id !== p.id))}>
                  <X aria-hidden />
                </IconButton>
              </div>
            ))}
            <Button size="sm" onClick={() => fileRef.current?.click()}>
              <Plus aria-hidden /> Attach file
            </Button>
            <input
              ref={fileRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (!f) return;
                if (f.size > MAX_FILE) return setError("Files must be 10 MB or smaller.");
                setPendingFiles([...pendingFiles, { id: crypto.randomUUID(), file: f }]);
              }}
            />
          </div>

          {error ? (
            <div role="alert" className="rounded-sm border border-danger px-3 py-2 text-[13px] text-danger" data-testid="editor-error">
              {error}
            </div>
          ) : null}
        </div>
      )}

      <Modal open={generatorFor !== null} onClose={() => setGeneratorFor(null)} title="Generate password">
        {generatorFor ? (
          <GeneratorPanel
            onUse={(v) => {
              setData({ [generatorFor]: v });
              setGeneratorFor(null);
            }}
          />
        ) : null}
      </Modal>
    </Modal>
  );
}
