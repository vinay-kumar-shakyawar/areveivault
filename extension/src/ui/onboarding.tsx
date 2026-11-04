import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { CheckCircle2, FileUp, ShieldCheck, Trash2 } from "lucide-react";
import { rpc } from "./rpc";

/**
 * Replace Chrome's password manager (architecture §13.6):
 * 1) export Chrome passwords to CSV, 2) import, 3) delete the CSV,
 * 4) with consent, turn off Chrome's own password saving.
 */

function ChromeSaving() {
  const [granted, setGranted] = useState<boolean | null>(null);
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [control, setControl] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const read = async () => {
    const has = await chrome.permissions.contains({ permissions: ["privacy"] });
    setGranted(has);
    if (has && chrome.privacy?.services?.passwordSavingEnabled) {
      const d = (await chrome.privacy.services.passwordSavingEnabled.get({})) as unknown as { value: boolean; levelOfControl: string };
      setEnabled(d.value as boolean);
      setControl(d.levelOfControl);
    }
  };
  useEffect(() => void read(), []);

  const turnOff = async () => {
    setError(null);
    // Must be called from a user gesture on an extension page.
    const ok = granted || (await chrome.permissions.request({ permissions: ["privacy"] }));
    if (!ok) return setError("Permission was not granted. Chrome will keep offering to save passwords.");
    try {
      await chrome.privacy.services.passwordSavingEnabled.set({ value: false });
    } catch (e: any) {
      setError(e?.message ?? "Could not change the setting (it may be managed by your organization).");
    }
    await read();
  };
  const revert = async () => {
    await chrome.privacy.services.passwordSavingEnabled.clear({});
    await read();
  };

  return (
    <section className="card">
      <h2>
        <ShieldCheck size={18} strokeWidth={1.5} /> Step 4 — Stop Chrome from offering to save passwords
      </h2>
      <p className="muted">
        So only Arevei Vault prompts you, we can turn off Chrome's built-in password saving. This needs the optional "privacy" permission and is reversible here
        at any time. Your existing Chrome passwords are not deleted.
      </p>
      <p>
        Current state:{" "}
        <strong>
          {enabled === null ? (granted === false ? "unknown (permission not granted)" : "…") : enabled ? "Chrome saving is ON" : "Chrome saving is OFF"}
        </strong>
        {control === "controlled_by_other_extensions" && " (controlled by another extension)"}
        {control === "not_controllable" && " (managed by policy)"}
      </p>
      {error && (
        <p className="banner danger" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        {enabled !== false && (
          <button className="primary" onClick={turnOff}>
            Turn off Chrome password saving
          </button>
        )}
        {enabled === false && control === "controlled_by_this_extension" && (
          <button className="secondary" onClick={revert}>
            Restore Chrome's default
          </button>
        )}
      </div>
    </section>
  );
}

function Import() {
  const [status, setStatus] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [format, setFormat] = useState("chrome");
  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setBusy(true);
    setStatus(null);
    const text = await f.text();
    const r = await rpc("importCsv", { format, text });
    setBusy(false);
    if (r?.error) return setStatus(r.error);
    setStatus(`Imported ${r.imported} item(s) into your Personal Vault.`);
    setSkipped(r.skipped ?? []);
  };
  return (
    <section className="card">
      <h2>
        <FileUp size={18} strokeWidth={1.5} /> Step 2 — Import the CSV
      </h2>
      <p className="muted">The file is read and encrypted on this device; only ciphertext is uploaded. Unlock the vault from the toolbar button first.</p>
      <label>
        Format{" "}
        <select className="input" value={format} onChange={(e) => setFormat(e.target.value)}>
          <option value="chrome">Chrome / Google Password Manager (CSV)</option>
          <option value="bitwarden">Bitwarden (CSV)</option>
          <option value="one_password">1Password (CSV)</option>
          <option value="last_pass">LastPass (CSV)</option>
          <option value="generic">Other CSV</option>
        </select>
      </label>
      <input type="file" accept=".csv,text/csv" disabled={busy} onChange={(e) => void onFile(e.target.files?.[0])} aria-label="Choose CSV file" />
      {busy && <p>Encrypting and uploading…</p>}
      {status && (
        <p role="status">
          <CheckCircle2 size={14} strokeWidth={1.5} /> {status}
        </p>
      )}
      {skipped.length > 0 && (
        <details>
          <summary>{skipped.length} row(s) skipped</summary>
          <ul>
            {skipped.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function App() {
  const [deleted, setDeleted] = useState(false);
  return (
    <main className="onboarding">
      <h1>Set up Arevei Vault</h1>
      <p className="muted">Move your saved passwords out of Chrome and make Arevei Vault your only password manager.</p>
      <section className="card">
        <h2>Step 1 — Export your Chrome passwords</h2>
        <ol>
          <li>
            Open <code>chrome://password-manager/settings</code> in a new tab (copy and paste it; extensions can't open it for you).
          </li>
          <li>Under "Export passwords", choose Download file and confirm with your device password.</li>
          <li>Chrome saves a file named like "Chrome Passwords.csv". It contains your passwords in plain text.</li>
        </ol>
      </section>
      <Import />
      <section className="card">
        <h2>
          <Trash2 size={18} strokeWidth={1.5} /> Step 3 — Delete the exported file
        </h2>
        <p>
          The CSV is unencrypted. Delete it now and empty your Recycle Bin / Trash. Also check that it wasn't synced to OneDrive, iCloud or Google Drive.
        </p>
        <label className="check">
          <input type="checkbox" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} /> I deleted the CSV file
        </label>
        {!deleted && <p className="banner warning">Reminder: the exported CSV is still on your device until you delete it.</p>}
      </section>
      <ChromeSaving />
    </main>
  );
}

createRoot(document.getElementById("app")!).render(<App />);
