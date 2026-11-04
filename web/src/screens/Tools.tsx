import { useRef, useState } from "react";
import { Download, FileUp, ShieldAlert } from "lucide-react";
import { nowSecs, type Item, type VaultSummary } from "@arevei/client";
import { Button, Field, Input, Modal, Select, Status, Toggle } from "@arevei/ui";
import { StrengthView, useStrength } from "../components/PasswordStrength";
import { api, audit, bump, engine, errorMessage, getState, reauth, savePrefs, sync } from "../lib/app";
import { downloadBytes } from "../lib/emergencyKit";
import { useEngine } from "../lib/hooks";
import { toast } from "../lib/toast";

type Format = "chrome" | "bitwarden" | "bitwarden_json" | "one_password" | "last_pass" | "generic" | "arevei";

const FORMATS: { id: Format; label: string; hint: string }[] = [
  { id: "chrome", label: "Chrome / Google Password Manager (CSV)", hint: "chrome://password-manager/settings → Export passwords" },
  { id: "bitwarden", label: "Bitwarden (CSV)", hint: "Tools → Export vault → .csv" },
  { id: "bitwarden_json", label: "Bitwarden (JSON, unencrypted)", hint: "Tools → Export vault → .json" },
  { id: "one_password", label: "1Password (CSV)", hint: "File → Export → CSV" },
  { id: "last_pass", label: "LastPass (CSV)", hint: "Advanced options → Export" },
  { id: "generic", label: "Generic CSV", hint: "Needs a header row with name/url/username/password/notes columns" },
  { id: "arevei", label: "Arevei Vault encrypted export", hint: "A file created by Export below" },
];

interface Parsed {
  items: { item: Item; folder?: string | null; favorite?: boolean }[];
  skipped: string[];
}

export function ToolsScreen() {
  return (
    <div className="mx-auto max-w-[820px] space-y-5 p-5 sm:p-6">
      <ImportSection />
      <ExportSection />
    </div>
  );
}

function ImportSection() {
  const { data: vl } = useEngine<{ vaults: VaultSummary[] }>("list_vaults", {});
  const writable = (vl?.vaults ?? []).filter((v) => v.unlocked && v.role !== "read_only");
  const [format, setFormat] = useState<Format>("chrome");
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [parsed, setParsed] = useState<Parsed | null>(null);
  const [dest, setDest] = useState("");
  const [folderAsTag, setFolderAsTag] = useState(true);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const parse = async () => {
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      if (format === "arevei") {
        const entries = await engine.call<{ location: string; item: Item }[]>("import_encrypted", { file: text, password });
        setParsed({ items: entries.map((e) => ({ item: e.item, folder: e.location })), skipped: [] });
      } else {
        setParsed(await engine.call<Parsed>("import_parse", { format, text }));
      }
      setDest((d) => d || writable.find((v) => v.kind === "personal")?.id || writable[0]?.id || "");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const runImport = async () => {
    if (!parsed || !dest) return;
    setError(null);
    const total = parsed.items.length;
    setProgress({ done: 0, total });
    const rows: any[] = [];
    const favs: string[] = [];
    let failed = 0;
    let next = 0;
    const worker = async () => {
      while (next < total) {
        const i = next++;
        const { item, folder, favorite } = parsed.items[i];
        const tags = new Set(item.tags ?? []);
        if (folderAsTag && folder) tags.add(folder);
        try {
          const req = await engine.call("encrypt_item", { vault_id: dest, item: { ...item, tags: [...tags] }, now: nowSecs() });
          rows.push(await api.putItem(req));
          if (favorite) favs.push(req.id);
        } catch {
          failed++;
        }
        setProgress({ done: rows.length + failed, total });
      }
    };
    await Promise.all(Array.from({ length: 6 }, worker));
    await sync.applyItemRows(rows);
    if (favs.length) await savePrefs({ ...getState().prefs, favorites: [...getState().prefs.favorites, ...favs] });
    bump();
    setProgress(null);
    setParsed(null);
    setFile(null);
    if (failed) toast.error(`Imported ${rows.length} items; ${failed} failed.`);
    else toast.success(`Imported ${rows.length} items.`);
    if (format !== "arevei") toast.info("Delete the exported file from your computer — it contains passwords in plain text.");
  };

  const fmt = FORMATS.find((f) => f.id === format)!;
  return (
    <section className="av-card p-5" data-testid="import-section">
      <h3 className="flex items-center gap-2 text-[15px] font-semibold">
        <FileUp className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Import
      </h3>
      <p className="mt-1 text-[13px] text-muted">Files are read and encrypted on this device. Nothing is uploaded in plaintext.</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <Field label="Source" htmlFor="imp-format" hint={fmt.hint}>
          <Select id="imp-format" value={format} onChange={(e) => (setFormat(e.target.value as Format), setParsed(null))} data-testid="import-format">
            {FORMATS.map((f) => (
              <option key={f.id} value={f.id}>
                {f.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="File" htmlFor="imp-file">
          <div className="flex items-center gap-2">
            <Button onClick={() => fileRef.current?.click()}>Choose file</Button>
            <span className="truncate text-[13px] text-muted">{file?.name ?? "No file selected"}</span>
            <input
              id="imp-file"
              ref={fileRef}
              type="file"
              accept=".csv,.json,text/csv,application/json"
              className="hidden"
              onChange={(e) => (setFile(e.target.files?.[0] ?? null), setParsed(null))}
              data-testid="import-file"
            />
          </div>
        </Field>
        {format === "arevei" ? (
          <Field label="Export password" htmlFor="imp-pw">
            <Input id="imp-pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
        ) : null}
      </div>
      <div className="mt-4">
        <Button onClick={() => void parse()} disabled={!file} data-testid="import-preview">
          Preview
        </Button>
      </div>
      {error ? (
        <div className="mt-3">
          <Status tone="danger">{error}</Status>
        </div>
      ) : null}

      {parsed ? (
        <div className="mt-5 space-y-4">
          <div className="text-[13px]" data-testid="import-count">
            <strong>{parsed.items.length}</strong> items ready to import
            {parsed.skipped.length ? <span className="text-muted"> · {parsed.skipped.length} rows skipped</span> : null}
          </div>
          <div className="max-h-64 overflow-auto rounded-sm border border-line">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-surface text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Title</th>
                  <th className="px-3 py-2 font-medium">Type</th>
                  <th className="px-3 py-2 font-medium">Username</th>
                  <th className="px-3 py-2 font-medium">Folder</th>
                </tr>
              </thead>
              <tbody>
                {parsed.items.slice(0, 50).map((r, i) => (
                  <tr key={i} className="border-t border-line">
                    <td className="max-w-[220px] truncate px-3 py-1.5">{r.item.title}</td>
                    <td className="px-3 py-1.5 text-muted">{r.item.data.type}</td>
                    <td className="max-w-[200px] truncate px-3 py-1.5 text-muted">{r.item.data.username ?? ""}</td>
                    <td className="px-3 py-1.5 text-muted">{r.folder ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {parsed.skipped.length ? (
            <details className="text-[12px] text-muted">
              <summary className="cursor-pointer">Skipped rows</summary>
              <ul className="mt-1 list-disc pl-5">
                {parsed.skipped.slice(0, 50).map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </details>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Destination vault" htmlFor="imp-dest">
              <Select id="imp-dest" value={dest} onChange={(e) => setDest(e.target.value)} data-testid="import-dest">
                {writable.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.client_name ? `${v.client_name} / ${v.name}` : v.name}
                  </option>
                ))}
              </Select>
            </Field>
            <div className="flex items-end justify-between gap-3 pb-2">
              <span className="text-[13px]">Turn folders into tags</span>
              <Toggle checked={folderAsTag} onChange={setFolderAsTag} label="Turn folders into tags" />
            </div>
          </div>
          {progress ? (
            <div className="space-y-1" role="progressbar" aria-valuemin={0} aria-valuemax={progress.total} aria-valuenow={progress.done}>
              <div className="h-1.5 overflow-hidden rounded-full bg-raised">
                <div className="h-full bg-silver-strong transition-all" style={{ width: `${(100 * progress.done) / Math.max(1, progress.total)}%` }} />
              </div>
              <div className="text-[12px] text-muted">
                {progress.done} / {progress.total}
              </div>
            </div>
          ) : (
            <Button variant="primary" onClick={() => void runImport()} disabled={!dest || parsed.items.length === 0} data-testid="import-run">
              Import {parsed.items.length} items
            </Button>
          )}
        </div>
      ) : null}
    </section>
  );
}

function ExportSection() {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [csvOpen, setCsvOpen] = useState(false);
  const [master, setMaster] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = useStrength(pw);
  const orgId = getState().session?.org_id ?? "org";
  const stamp = new Date().toISOString().slice(0, 10);

  const exportEncrypted = async () => {
    setError(null);
    if (!strength || strength.score < 3) return setError("Choose a stronger export password.");
    if (pw !== pw2) return setError("Export passwords don't match.");
    setBusy(true);
    try {
      const { file } = await engine.call<{ file: string }>("export_encrypted", { password: pw });
      downloadBytes(file, `arevei-vault-export-${stamp}.json`, "application/json");
      audit.record("export", orgId, null, "org");
      setPw("");
      setPw2("");
      toast.success("Encrypted export downloaded.");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const exportCsv = async () => {
    setError(null);
    setBusy(true);
    try {
      await reauth(master);
      const { csv } = await engine.call<{ csv: string }>("export_csv", {});
      downloadBytes(csv, `arevei-vault-PLAINTEXT-${stamp}.csv`, "text/csv");
      audit.record("export", orgId, null, "org");
      setCsvOpen(false);
      setMaster("");
      setAck(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="av-card p-5" data-testid="export-section">
      <h3 className="flex items-center gap-2 text-[15px] font-semibold">
        <Download className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Export
      </h3>
      <p className="mt-1 text-[13px] text-muted">Exports include every item you can access. Exports are audit-logged.</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <Field label="Export password" htmlFor="exp-pw">
          <Input id="exp-pw" type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        </Field>
        <Field label="Confirm export password" htmlFor="exp-pw2">
          <Input id="exp-pw2" type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
        </Field>
      </div>
      <div className="mt-3">
        <StrengthView strength={strength} />
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => void exportEncrypted()} loading={busy && !csvOpen}>
          Download encrypted export
        </Button>
        <Button variant="danger" onClick={() => (setCsvOpen(true), setError(null))}>
          Export plaintext CSV…
        </Button>
      </div>
      {error && !csvOpen ? (
        <div className="mt-3">
          <Status tone="danger">{error}</Status>
        </div>
      ) : null}

      <Modal
        open={csvOpen}
        onClose={() => setCsvOpen(false)}
        title="Export unencrypted CSV"
        footer={
          <>
            <Button onClick={() => setCsvOpen(false)}>Cancel</Button>
            <Button variant="danger" disabled={!ack || !master} loading={busy} onClick={() => void exportCsv()}>
              Export plaintext
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="flex gap-3 rounded-sm border border-danger p-3 text-[13px]">
            <ShieldAlert className="h-5 w-5 flex-none text-danger" strokeWidth={1.5} aria-hidden />
            <div>
              <div className="font-semibold text-danger">Every password will be readable by anyone who gets this file.</div>
              <div className="mt-1 text-muted">
                It may be synced to cloud storage, indexed by your OS, or recovered after deletion. Use the encrypted export instead unless you're migrating to another password manager, and delete the file immediately afterwards.
              </div>
            </div>
          </div>
          <Field label="Master password (re-authentication)" htmlFor="csv-master">
            <Input id="csv-master" type="password" autoComplete="current-password" value={master} onChange={(e) => setMaster(e.target.value)} />
          </Field>
          <label className="flex items-start gap-2 text-[13px]">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5" />
            I understand this file is not encrypted.
          </label>
          {error ? <Status tone="danger">{error}</Status> : null}
        </div>
      </Modal>
    </section>
  );
}
