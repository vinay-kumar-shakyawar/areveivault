import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Download, KeyRound, ShieldCheck } from "lucide-react";
import type { SignupPending } from "@arevei/client";
import { Button, Field, Input, Toggle } from "@arevei/ui";
import { AuthLayout, ErrorNote } from "../components/AuthLayout";
import { useStrength, StrengthView } from "../components/PasswordStrength";
import { errorMessage, loginMfa, loginStart, signupConfirm, signupStart } from "../lib/app";
import { buildEmergencyKit, downloadBytes } from "../lib/emergencyKit";
import { QrCode } from "../lib/qr";
import { secretKeyStore } from "../lib/secretKeyStore";
import { settings } from "../lib/settings";

function initialMode(): "login" | "signup" {
  const p = new URLSearchParams(location.search);
  return p.has("invite") || location.pathname.startsWith("/signup") ? "signup" : "login";
}

export function AuthScreen() {
  const [mode, setMode] = useState<"login" | "signup">(initialMode);
  return mode === "login" ? <Login onSignup={() => setMode("signup")} /> : <Signup onLogin={() => setMode("login")} />;
}

// ---------------------------------------------------------------- login
function Login({ onSignup }: { onSignup: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [remembered, setRemembered] = useState(false);
  const [mfa, setMfa] = useState<{ token: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lockMsg = useMemo(() => {
    const m = sessionStorage.getItem("arevei-lock-message");
    sessionStorage.removeItem("arevei-lock-message");
    return m;
  }, []);

  const lookupKey = async (e: string) => {
    const sk = await secretKeyStore.load(e.trim().toLowerCase());
    setRemembered(!!sk);
    if (sk) setSecretKey(sk);
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (!mfa) {
        const r = await loginStart(email, password, secretKey);
        setMfa({ token: r.mfaToken });
      } else {
        await loginMfa(mfa.token, code, email, secretKey);
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      footer={
        <>
          New to Arevei Vault?{" "}
          <button className="text-fg underline underline-offset-2" onClick={onSignup}>
            Create an account
          </button>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4" data-testid="login-form">
        <div>
          <h1 className="text-lg font-semibold">{mfa ? "Two-step verification" : "Sign in"}</h1>
          <p className="mt-1 text-[13px] text-muted">
            {mfa ? "Enter the 6-digit code from your authenticator app." : "Your master password never leaves this device."}
          </p>
        </div>
        {lockMsg && !mfa ? <p className="text-[13px] text-muted">{lockMsg}</p> : null}
        {!mfa ? (
          <>
            <Field label="Email" htmlFor="email">
              <Input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} onBlur={() => void lookupKey(email)} data-testid="login-email" />
            </Field>
            <Field label="Master password" htmlFor="password">
              <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} data-testid="login-password" />
            </Field>
            <Field label="Secret Key" htmlFor="sk" hint={remembered ? "Remembered on this device." : "From your Emergency Kit (AV1-…)."}>
              <Input id="sk" mono autoComplete="off" spellCheck={false} required value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="AV1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX" data-testid="login-secret-key" />
            </Field>
          </>
        ) : (
          <Field label="Authentication code" htmlFor="code">
            <Input id="code" inputMode="numeric" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} mono data-testid="login-totp" />
          </Field>
        )}
        <ErrorNote error={error} />
        <Button type="submit" variant="primary" block loading={busy} data-testid="login-submit">
          {mfa ? "Verify" : busy ? "Deriving keys…" : "Sign in"}
        </Button>
      </form>
    </AuthLayout>
  );
}

// ---------------------------------------------------------------- signup
type Step = "form" | "secret" | "confirm" | "totp";

function Signup({ onLogin }: { onLogin: () => void }) {
  const invite = new URLSearchParams(location.search).get("invite");
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState<SignupPending | null>(null);
  const [kitDownloaded, setKitDownloaded] = useState(false);
  const [last4, setLast4] = useState("");
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(settings.get().rememberSecretKey);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = useStrength(password, [email, email.split("@")[0], "arevei", "vault"]);

  useEffect(() => setError(null), [step]);

  const submitForm = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    if (!strength || strength.score < 3) return setError("Choose a stronger master password (strength 3 of 4 or better).");
    if (password !== confirm) return setError("Passwords don't match.");
    setBusy(true);
    try {
      const p = await signupStart({ email, password, inviteToken: invite, createOrg: !invite });
      setPending(p);
      setPassword("");
      setConfirm("");
      setStep("secret");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const downloadKit = async () => {
    if (!pending) return;
    const bytes = await buildEmergencyKit({ email: email.trim().toLowerCase(), secretKey: pending.secretKey, signInUrl: location.origin, createdAt: new Date() });
    downloadBytes(bytes, "Arevei-Vault-Emergency-Kit.pdf", "application/pdf");
    setKitDownloaded(true);
  };

  const submitConfirm = (ev: FormEvent) => {
    ev.preventDefault();
    const expected = pending!.secretKey.replace(/-/g, "").slice(-4).toUpperCase();
    if (last4.trim().toUpperCase() !== expected) return setError("That doesn't match the last 4 characters of your Secret Key.");
    setStep("totp");
  };

  const submitTotp = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      settings.update({ rememberSecretKey: remember });
      await signupConfirm(pending!, email, code);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const stepNo = { form: 1, secret: 2, confirm: 3, totp: 4 }[step];

  return (
    <AuthLayout
      footer={
        step === "form" ? (
          <>
            Already have an account?{" "}
            <button className="text-fg underline underline-offset-2" onClick={onLogin}>
              Sign in
            </button>
          </>
        ) : null
      }
    >
      <div className="mb-5 text-[11px] font-semibold uppercase tracking-wider text-muted">Step {stepNo} of 4</div>

      {step === "form" && (
        <form onSubmit={submitForm} className="space-y-4" data-testid="signup-form">
          <div>
            <h1 className="text-lg font-semibold">{invite ? "Join your organization" : "Create your organization"}</h1>
            <p className="mt-1 text-[13px] text-muted">
              {invite ? "You were invited to Arevei Vault. An admin will approve your account after signup." : "You'll be the owner. Invite your team once you're in."}
            </p>
          </div>
          <Field label="Email" htmlFor="su-email">
            <Input id="su-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} data-testid="signup-email" />
          </Field>
          <Field label="Master password" htmlFor="su-pw" hint="Long and memorable beats short and complex. A passphrase of 4+ random words works well.">
            <Input id="su-pw" type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} data-testid="signup-password" />
          </Field>
          <StrengthView strength={strength} />
          <Field label="Confirm master password" htmlFor="su-pw2">
            <Input id="su-pw2" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} data-testid="signup-password-confirm" />
          </Field>
          <p className="text-[12px] text-muted">
            Arevei can't reset your master password. If you forget it, administrators can restore your access to shared client projects, but your Personal Vault can't be recovered.
          </p>
          <ErrorNote error={error} />
          <Button type="submit" variant="primary" block loading={busy} data-testid="signup-submit">
            {busy ? "Generating keys…" : "Continue"}
          </Button>
        </form>
      )}

      {step === "secret" && pending && (
        <div className="space-y-5">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold">
              <KeyRound className="h-5 w-5 text-silver-strong" strokeWidth={1.5} aria-hidden /> Your Secret Key
            </h1>
            <p className="mt-1 text-[13px] text-muted">
              Together with your master password, this key encrypts your vault. It's shown only now. Save your Emergency Kit somewhere safe and offline.
            </p>
          </div>
          <div className="rounded border border-line bg-bg px-4 py-4 text-center font-mono text-[15px] tracking-wide" data-testid="secret-key">
            {pending.secretKey}
          </div>
          <Button variant="primary" block onClick={() => void downloadKit()} data-testid="download-kit">
            <Download aria-hidden /> Download Emergency Kit (PDF)
          </Button>
          <Button block disabled={!kitDownloaded} onClick={() => setStep("confirm")} data-testid="kit-continue">
            I saved my Emergency Kit
          </Button>
        </div>
      )}

      {step === "confirm" && pending && (
        <form onSubmit={submitConfirm} className="space-y-4">
          <div>
            <h1 className="text-lg font-semibold">Confirm you saved it</h1>
            <p className="mt-1 text-[13px] text-muted">Type the last 4 characters of your Secret Key from the Emergency Kit (ignore the dashes).</p>
          </div>
          <Field label="Last 4 characters" htmlFor="last4">
            <Input id="last4" mono maxLength={4} autoComplete="off" required value={last4} onChange={(e) => setLast4(e.target.value)} data-testid="secret-key-last4" />
          </Field>
          <ErrorNote error={error} />
          <div className="flex gap-2">
            <Button onClick={() => setStep("secret")}>Back</Button>
            <Button type="submit" variant="primary" className="flex-1" data-testid="confirm-last4">
              Continue
            </Button>
          </div>
        </form>
      )}

      {step === "totp" && pending && (
        <form onSubmit={submitTotp} className="space-y-4">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold">
              <ShieldCheck className="h-5 w-5 text-silver-strong" strokeWidth={1.5} aria-hidden /> Set up two-step verification
            </h1>
            <p className="mt-1 text-[13px] text-muted">Required for every account. Scan with Google Authenticator, Authy, or another TOTP app.</p>
          </div>
          <div className="flex justify-center rounded border border-line bg-white p-3">
            <QrCode text={pending.otpauthUri} label="Two-step verification QR code" />
          </div>
          <div className="text-center">
            <div className="text-[12px] text-muted">Or enter this key manually</div>
            <div className="mt-1 break-all font-mono text-[13px]" data-testid="totp-secret">
              {pending.totpSecret}
            </div>
          </div>
          <Field label="6-digit code" htmlFor="totp">
            <Input id="totp" inputMode="numeric" autoComplete="one-time-code" mono required value={code} onChange={(e) => setCode(e.target.value)} data-testid="signup-totp" />
          </Field>
          <div className="flex items-center justify-between gap-3">
            <label className="text-[13px]" htmlFor="remember">
              Remember Secret Key on this device
            </label>
            <Toggle checked={remember} onChange={setRemember} label="Remember Secret Key on this device" />
          </div>
          <ErrorNote error={error} />
          <Button type="submit" variant="primary" block loading={busy} data-testid="signup-totp-submit">
            Verify and open vault
          </Button>
        </form>
      )}
    </AuthLayout>
  );
}
