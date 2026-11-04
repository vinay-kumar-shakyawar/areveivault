import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Button, Field, Input, LogoMark } from "@arevei/ui";
import { ErrorNote } from "../components/AuthLayout";
import { errorMessage, logout, unlock, useApp } from "../lib/app";
import { secretKeyStore } from "../lib/secretKeyStore";

export function UnlockScreen() {
  const { session } = useApp();
  const [password, setPassword] = useState("");
  const [needsKey, setNeedsKey] = useState(false);
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lockMsg = useMemo(() => {
    const m = sessionStorage.getItem("arevei-lock-message");
    sessionStorage.removeItem("arevei-lock-message");
    return m;
  }, []);

  useEffect(() => {
    if (session) void secretKeyStore.load(session.email).then((k) => setNeedsKey(!k));
  }, [session]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlock(password, needsKey ? secretKey : undefined);
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-full flex-col items-center justify-center px-4">
      <div className="w-full max-w-[360px] text-center">
        <div className="unlock-mark mb-6 flex justify-center">
          <LogoMark size={72} gradient />
        </div>
        <h1 className="silver-text text-xl font-semibold">Arevei Vault is locked</h1>
        <p className="mt-1 text-[13px] text-muted">{session?.email}</p>
        {lockMsg ? <p className="mt-2 text-[13px] text-muted">{lockMsg}</p> : null}
        <form onSubmit={submit} className="mt-6 space-y-3 text-left" data-testid="unlock-form">
          <Field label="Master password" htmlFor="unlock-pw">
            <Input id="unlock-pw" type="password" autoFocus autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} data-testid="unlock-password" />
          </Field>
          {needsKey ? (
            <Field label="Secret Key" htmlFor="unlock-sk" hint="Not remembered on this device.">
              <Input id="unlock-sk" mono required value={secretKey} onChange={(e) => setSecretKey(e.target.value)} data-testid="unlock-secret-key" />
            </Field>
          ) : null}
          <ErrorNote error={error} />
          <Button type="submit" variant="primary" block loading={busy} data-testid="unlock-submit">
            {busy ? "Unlocking…" : "Unlock"}
          </Button>
        </form>
        <button className="mt-6 text-[13px] text-muted underline underline-offset-2 hover:text-fg" onClick={() => void logout()}>
          Sign out
        </button>
      </div>
    </div>
  );
}
