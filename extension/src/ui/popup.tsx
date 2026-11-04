import React, { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { AlertTriangle, Copy, ExternalLink, KeyRound, Lock, LogOut, Search, ShieldAlert, Timer, User } from "lucide-react";
import { rpc } from "./rpc";
import { initials } from "./dom";

interface State {
  signedIn: boolean;
  unlocked: boolean;
  email: string | null;
  hasSecretKey: boolean;
  mfaPending: boolean;
  vaultOrigin: string;
}

interface Summary {
  id: string;
  title: string;
  subtitle: string;
  type: string;
  has_totp: boolean;
  host: string | null;
}

// Keep the service worker alive while the popup is open.
const keepAlive = chrome.runtime.connect({ name: "popup" });

function Logo() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
      <defs>
        <linearGradient id="av-silver" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#e8e8e8" />
          <stop offset=".5" stopColor="#a8a9ad" />
          <stop offset="1" stopColor="#d4d4d4" />
        </linearGradient>
      </defs>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="var(--logo-fill)" />
      <circle cx="12" cy="11" r="2" fill="var(--bg)" />
      <path d="M12 13v3" stroke="var(--bg)" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function Header({ state, onLock, onSignOut }: { state: State; onLock?: () => void; onSignOut?: () => void }) {
  return (
    <header className="pop-head">
      <Logo />
      <span className="brand">Arevei Vault</span>
      <span className="spacer" />
      <a className="icon-btn" href={state.vaultOrigin} target="_blank" rel="noreferrer" title="Open web vault" aria-label="Open web vault">
        <ExternalLink size={16} strokeWidth={1.5} />
      </a>
      {onLock && (
        <button className="icon-btn" onClick={onLock} title="Lock" aria-label="Lock">
          <Lock size={16} strokeWidth={1.5} />
        </button>
      )}
      {onSignOut && (
        <button className="icon-btn" onClick={onSignOut} title="Sign out" aria-label="Sign out">
          <LogOut size={16} strokeWidth={1.5} />
        </button>
      )}
    </header>
  );
}

function SignIn({ onDone, mfaPending }: { onDone: () => void; mfaPending: boolean }) {
  const [step, setStep] = useState<"creds" | "mfa">(mfaPending ? "mfa" : "creds");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = step === "creds" ? await rpc("signin", { email, password, secretKey }) : await rpc("mfa", { code });
    setBusy(false);
    setPassword("");
    if (r?.error) return setError(r.error);
    if (step === "creds") setStep("mfa");
    else onDone();
  };

  return (
    <form className="pad stack" onSubmit={submit}>
      <h1>{step === "creds" ? "Sign in" : "Two-factor code"}</h1>
      {step === "creds" ? (
        <>
          <label>
            Email
            <input className="input" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label>
            Master password
            <input className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <label>
            Secret Key
            <input className="input mono" placeholder="AV1-XXXXXX-…" required value={secretKey} onChange={(e) => setSecretKey(e.target.value)} spellCheck={false} />
          </label>
        </>
      ) : (
        <label>
          6-digit code from your authenticator
          <input className="input mono" inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
        </label>
      )}
      {error && (
        <p className="banner danger" role="alert">
          <AlertTriangle size={14} strokeWidth={1.5} /> {error}
        </p>
      )}
      <button className="primary" disabled={busy}>
        {busy ? "Working…" : step === "creds" ? "Continue" : "Verify"}
      </button>
    </form>
  );
}

function Unlock({ state, onDone }: { state: State; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const r = await rpc("unlock", { password, secretKey: state.hasSecretKey ? undefined : secretKey });
    setBusy(false);
    setPassword("");
    if (r?.error) setError(r.error);
    else onDone();
  };
  return (
    <form className="pad stack unlock" onSubmit={submit}>
      <div className="unlock-mark">
        <Logo />
      </div>
      <h1>Vault locked</h1>
      <p className="muted">{state.email}</p>
      <label>
        Master password
        <input className="input" type="password" autoComplete="current-password" autoFocus required value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {!state.hasSecretKey && (
        <label>
          Secret Key
          <input className="input mono" required value={secretKey} onChange={(e) => setSecretKey(e.target.value)} spellCheck={false} />
        </label>
      )}
      {error && (
        <p className="banner danger" role="alert">
          {error}
        </p>
      )}
      <button className="primary" disabled={busy}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
    </form>
  );
}

function TotpBadge({ id }: { id: string }) {
  const [t, setT] = useState<{ code: string; remaining: number; period: number } | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const r = await rpc("totp", { itemId: id });
      if (alive && !r?.error) setT(r);
    };
    void tick();
    const iv = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(iv);
    };
  }, [id]);
  if (!t) return null;
  return (
    <span className="totp mono" aria-label={`One-time code, ${t.remaining} seconds left`}>
      {t.code.slice(0, 3)} {t.code.slice(3)}
      <span className="countdown">
        <Timer size={12} strokeWidth={1.5} /> {t.remaining}s
      </span>
    </span>
  );
}

function Row({ it, onCopied }: { it: Summary; onCopied: (what: string) => void }) {
  const copy = async (field: string, label: string) => {
    const r = await rpc("copy", { itemId: it.id, field });
    if (r?.error) return;
    if (typeof r.value === "string") {
      // Firefox fallback (no offscreen document): clear after 30s only while the popup stays open.
      await navigator.clipboard.writeText(r.value);
      setTimeout(() => void navigator.clipboard.writeText(""), 30_000);
    }
    onCopied(label);
  };
  return (
    <li className="row">
      <span className="avatar">{initials(it.title)}</span>
      <span className="text">
        <span className="title">{it.title}</span>
        <span className="sub">{it.subtitle || it.host || "—"}</span>
        {it.has_totp && <TotpBadge id={it.id} />}
      </span>
      <span className="row-actions">
        {(it.type === "login" || it.type === "server") && (
          <>
            <button className="icon-btn" title="Copy username" aria-label={`Copy username for ${it.title}`} onClick={() => copy("username", "Username")}>
              <User size={16} strokeWidth={1.5} />
            </button>
            <button className="icon-btn" title="Copy password" aria-label={`Copy password for ${it.title}`} onClick={() => copy("password", "Password")}>
              <KeyRound size={16} strokeWidth={1.5} />
            </button>
          </>
        )}
        {it.has_totp && (
          <button className="icon-btn" title="Copy one-time code" aria-label={`Copy one-time code for ${it.title}`} onClick={() => copy("totp", "Code")}>
            <Copy size={16} strokeWidth={1.5} />
          </button>
        )}
      </span>
    </li>
  );
}

function Vault({ onLocked }: { onLocked: () => void }) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<Summary[]>([]);
  const [site, setSite] = useState<any>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number>();

  useEffect(() => {
    void rpc("tabMatches").then((r) => (r?.error === "locked" ? onLocked() : setSite(r)));
  }, [onLocked]);
  useEffect(() => {
    const t = setTimeout(async () => {
      const r = await rpc("listItems", { query });
      if (r?.error === "locked") onLocked();
      else setItems(r.items ?? []);
    }, 120);
    return () => clearTimeout(t);
  }, [query, onLocked]);

  const copied = useCallback((what: string) => {
    setToast(`${what} copied — clears in 30s`);
    clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 2500);
  }, []);

  const host = site?.url ? new URL(site.url).host : null;
  return (
    <div className="vault">
      {site?.lookalike && (
        <div className="banner danger" role="alert">
          <ShieldAlert size={16} strokeWidth={1.5} /> <strong>Possible phishing:</strong> {site.lookalike.page_domain} {site.lookalike.reason} ({site.lookalike.imitates}).
        </div>
      )}
      {site?.insecure_page && !site?.lookalike && (
        <div className="banner warning" role="status">
          <AlertTriangle size={16} strokeWidth={1.5} /> This page is not secure (HTTP).
        </div>
      )}
      <div className="search">
        <Search size={16} strokeWidth={1.5} aria-hidden="true" />
        <input className="input" placeholder="Search vault" aria-label="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
      </div>
      {!query && host && (
        <section>
          <h2>On {host}</h2>
          <ul className="list">
            {(site.matches as Summary[]).map((it) => (
              <Row key={it.id} it={it} onCopied={copied} />
            ))}
            {!site.matches.length && <li className="muted empty">No logins for this site.</li>}
          </ul>
        </section>
      )}
      <section>
        <h2>{query ? "Results" : "All items"}</h2>
        <ul className="list">
          {items.map((it) => (
            <Row key={it.id} it={it} onCopied={copied} />
          ))}
          {!items.length && <li className="muted empty">Nothing found.</li>}
        </ul>
      </section>
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

function App() {
  const [state, setState] = useState<State | null>(null);
  const refresh = useCallback(() => void rpc<State>("state").then(setState), []);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    const iv = setInterval(() => keepAlive.postMessage({ type: "ping" }), 20_000);
    return () => clearInterval(iv);
  }, []);
  if (!state) return null;
  if (!state.signedIn)
    return (
      <>
        <Header state={state} />
        <SignIn onDone={refresh} mfaPending={state.mfaPending} />
      </>
    );
  if (!state.unlocked)
    return (
      <>
        <Header state={state} onSignOut={() => void rpc("signout").then(refresh)} />
        <Unlock state={state} onDone={refresh} />
      </>
    );
  return (
    <>
      <Header state={state} onLock={() => void rpc("lock").then(refresh)} onSignOut={() => void rpc("signout").then(refresh)} />
      <Vault onLocked={refresh} />
    </>
  );
}

createRoot(document.getElementById("app")!).render(<App />);
