import { useEffect, useState, useSyncExternalStore } from "react";
import { Download, KeyRound, LogOut, MonitorSmartphone, ShieldCheck } from "lucide-react";
import { Button, Field, Input, Modal, Select, Status, Toggle } from "@arevei/ui";
import { api, engine, errorMessage, logout, reauth, useApp } from "../lib/app";
import { buildEmergencyKit, downloadBytes } from "../lib/emergencyKit";
import { secretKeyStore } from "../lib/secretKeyStore";
import { settings } from "../lib/settings";
import { toast } from "../lib/toast";

export function SettingsScreen() {
  const s = useSyncExternalStore(settings.subscribe, settings.get);
  const { session, sync } = useApp();
  const [myFp, setMyFp] = useState("");
  const [orgFp, setOrgFp] = useState("");
  const [devices, setDevices] = useState<any[] | null>(null);
  const [skOpen, setSkOpen] = useState(false);

  useEffect(() => {
    void engine.call<{ fingerprint: string }>("my_fingerprint").then((r) => setMyFp(r.fingerprint));
    void api
      .devices()
      .then(setDevices)
      .catch(() => setDevices([]));
  }, []);
  useEffect(() => {
    if (sync?.org) void engine.call<{ fingerprint: string }>("fingerprint", { public_key: sync.org.org_sign_pk }).then((r) => setOrgFp(r.fingerprint));
  }, [sync?.org]);

  const Row = ({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) => (
    <div className="flex flex-col gap-2 border-b border-line px-4 py-4 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <div className="text-[14px]">{label}</div>
        {hint ? <div className="mt-0.5 text-[12px] text-muted">{hint}</div> : null}
      </div>
      <div className="flex-none">{children}</div>
    </div>
  );

  const revoke = async (id: string) => {
    try {
      await api.revokeDevice(id);
      setDevices((d) => d?.filter((x) => x.id !== id) ?? null);
      toast.success("Device signed out.");
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  return (
    <div className="mx-auto max-w-[820px] space-y-5 p-5 sm:p-6">
      <section className="av-card">
        <h3 className="border-b border-line px-4 py-3 text-[14px] font-semibold">Security</h3>
        <Row label="Auto-lock after inactivity" hint="Also locks when the browser closes.">
          <Select aria-label="Auto-lock minutes" value={String(s.autoLockMinutes)} onChange={(e) => settings.update({ autoLockMinutes: Number(e.target.value) })} data-testid="setting-autolock">
            {[1, 2, 5, 10, 15, 30, 60].map((m) => (
              <option key={m} value={m}>
                {m} minute{m === 1 ? "" : "s"}
              </option>
            ))}
          </Select>
        </Row>
        <Row label="Clear clipboard after copying" hint="OS clipboard history (e.g. Windows Win+V) may still keep a copy.">
          <Select aria-label="Clipboard clear seconds" value={String(s.clipboardSeconds)} onChange={(e) => settings.update({ clipboardSeconds: Number(e.target.value) })}>
            {[10, 20, 30, 60, 90].map((n) => (
              <option key={n} value={n}>
                {n} seconds
              </option>
            ))}
          </Select>
        </Row>
        <Row label="Remember Secret Key on this device" hint="Stored encrypted with a non-extractable browser key. Useless without your master password.">
          <Toggle
            checked={s.rememberSecretKey}
            onChange={(v) => {
              settings.update({ rememberSecretKey: v });
              if (!v) void secretKeyStore.clear();
              toast.info(v ? "Secret Key will be remembered after your next unlock." : "Secret Key removed from this device.");
            }}
            label="Remember Secret Key on this device"
          />
        </Row>
        <Row label="Secret Key and Emergency Kit" hint="Requires your master password.">
          <Button onClick={() => setSkOpen(true)}>
            <KeyRound aria-hidden /> Show Secret Key
          </Button>
        </Row>
        <Row label="Change master password" hint="Requires the server endpoint PUT /account/password (not yet in the API).">
          <Button disabled title="Not available yet">
            Change…
          </Button>
        </Row>
      </section>

      <section className="av-card">
        <h3 className="border-b border-line px-4 py-3 text-[14px] font-semibold">Appearance</h3>
        <Row label="Theme">
          <Select aria-label="Theme" value={s.theme} onChange={(e) => settings.update({ theme: e.target.value as any })} data-testid="setting-theme">
            <option value="system">Match system</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </Select>
        </Row>
      </section>

      <section className="av-card">
        <h3 className="flex items-center gap-2 border-b border-line px-4 py-3 text-[14px] font-semibold">
          <ShieldCheck className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Identity verification
        </h3>
        <Row label="Your fingerprint" hint="Read this to an admin when they approve your account.">
          <code className="font-mono text-[13px]" data-testid="settings-my-fingerprint">
            {myFp}
          </code>
        </Row>
        <Row label="Organization signing key" hint="Pinned on this device the first time it was seen. Compare it with a colleague out of band; if it ever changes you'll get a hard error.">
          <code className="font-mono text-[13px]" data-testid="settings-org-fingerprint">
            {orgFp || "—"}
          </code>
        </Row>
      </section>

      <section className="av-card">
        <h3 className="flex items-center gap-2 border-b border-line px-4 py-3 text-[14px] font-semibold">
          <MonitorSmartphone className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden /> Devices
        </h3>
        {devices === null ? <div className="px-4 py-3 text-[13px] text-muted">Loading…</div> : null}
        {devices?.length === 0 ? <div className="px-4 py-3 text-[13px] text-muted">No devices listed.</div> : null}
        {devices?.map((d) => (
          <Row key={d.id} label={`${d.name}${d.current ? " (this device)" : ""}`} hint={`Last seen ${d.last_seen_at ? new Date(d.last_seen_at * 1000).toLocaleString() : "—"}`}>
            {!d.current ? (
              <Button size="sm" variant="danger" onClick={() => void revoke(d.id)}>
                Sign out
              </Button>
            ) : (
              <Status tone="success">Current</Status>
            )}
          </Row>
        ))}
      </section>

      <Button onClick={() => void logout()} data-testid="logout">
        <LogOut aria-hidden /> Sign out of {session?.email}
      </Button>

      <SecretKeyModal open={skOpen} onClose={() => setSkOpen(false)} email={session?.email ?? ""} />
    </div>
  );
}

function SecretKeyModal({ open, onClose, email }: { open: boolean; onClose: () => void; email: string }) {
  const [pw, setPw] = useState("");
  const [sk, setSk] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) {
      setPw("");
      setSk(null);
      setError(null);
    }
  }, [open]);

  const reveal = async () => {
    setBusy(true);
    setError(null);
    try {
      setSk(await reauth(pw));
      setPw("");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Your Secret Key">
      {sk ? (
        <div className="space-y-4">
          <div className="rounded border border-line bg-bg px-4 py-4 text-center font-mono text-[15px]">{sk}</div>
          <Button
            variant="primary"
            block
            onClick={() =>
              void buildEmergencyKit({ email, secretKey: sk, signInUrl: location.origin, createdAt: new Date() }).then((b) =>
                downloadBytes(b, "Arevei-Vault-Emergency-Kit.pdf", "application/pdf"),
              )
            }
          >
            <Download aria-hidden /> Download Emergency Kit
          </Button>
        </div>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void reveal();
          }}
        >
          <Field label="Master password" htmlFor="sk-pw">
            <Input id="sk-pw" type="password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} />
          </Field>
          {error ? <Status tone="danger">{error}</Status> : null}
          <Button type="submit" variant="primary" block loading={busy}>
            Show Secret Key
          </Button>
        </form>
      )}
    </Modal>
  );
}
