import { useEffect, useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { IconButton, SecretText, type CharRun } from "@arevei/ui";
import { audit, copyText, engine } from "../lib/app";
import { useNow } from "../lib/hooks";

export interface AuditCtx {
  itemId: string;
  vaultId: string;
}

/** Labeled read-only value with copy (and reveal for secrets). */
export function ValueRow({
  label,
  value,
  secret,
  mono,
  copyOnly,
  ctx,
  multiline,
  testId,
}: {
  label: string;
  value: string;
  secret?: boolean;
  mono?: boolean;
  copyOnly?: boolean;
  ctx: AuditCtx;
  multiline?: boolean;
  testId?: string;
}) {
  const [revealed, setRevealed] = useState(false);
  const [runs, setRuns] = useState<CharRun[]>([]);
  useEffect(() => {
    setRevealed(false);
  }, [value, ctx.itemId]);
  useEffect(() => {
    if (revealed && secret) void engine.call<CharRun[]>("tokenize", { password: value }).then(setRuns);
    else setRuns([]);
  }, [revealed, secret, value]);

  if (!value) return null;
  const toggle = () => {
    if (!revealed) audit.record("item_reveal", ctx.itemId, ctx.vaultId);
    setRevealed(!revealed);
  };

  return (
    <div className="group flex items-start gap-3 border-b border-line px-4 py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="text-[12px] text-muted">{label}</div>
        <div className={`mt-0.5 text-[14px] ${mono ? "font-mono text-[13px]" : ""} ${multiline ? "whitespace-pre-wrap break-all" : "break-all"}`} data-testid={testId}>
          {secret ? (
            revealed ? (
              multiline ? (
                <span className="av-secret whitespace-pre-wrap">{value}</span>
              ) : (
                <SecretText runs={runs} testId={testId ? `${testId}-revealed` : undefined} />
              )
            ) : (
              <span className="av-secret av-secret--masked">••••••••••••</span>
            )
          ) : (
            value
          )}
        </div>
      </div>
      <div className="flex flex-none gap-0.5">
        {secret && !copyOnly ? (
          <IconButton label={revealed ? `Hide ${label}` : `Reveal ${label}`} onClick={toggle} data-testid={testId ? `${testId}-reveal` : undefined}>
            {revealed ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
          </IconButton>
        ) : null}
        <IconButton label={`Copy ${label}`} onClick={() => void copyText(value, label, ctx)} data-testid={testId ? `${testId}-copy` : undefined}>
          <Copy aria-hidden />
        </IconButton>
      </div>
    </div>
  );
}

/** Live TOTP code with countdown ring (computed in the engine every second). */
export function TotpRow({ ctx, secret, label = "One-time code" }: { ctx: AuditCtx; secret?: string; label?: string }) {
  const now = useNow(1000);
  const [code, setCode] = useState<{ code: string; remaining: number; period: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const sec = Math.floor(now / 1000);
  useEffect(() => {
    const args = secret ? { secret, now: sec } : { item_id: ctx.itemId, now: sec };
    engine
      .call<{ code: string; remaining: number; period: number }>("totp", args)
      .then((c) => {
        setCode(c);
        setErr(null);
      })
      .catch((e: Error) => setErr(e.message));
  }, [sec, ctx.itemId, secret]);

  if (err) return <div className="px-4 py-3 text-[13px] text-danger">TOTP error: {err}</div>;
  if (!code) return null;
  const c = 2 * Math.PI * 9;
  const pretty = code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code;
  return (
    <div className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="text-[12px] text-muted">{label}</div>
        <div className="mt-0.5 font-mono text-[20px] tracking-[0.12em]" data-testid="totp-code" data-code={code.code}>
          {pretty}
        </div>
      </div>
      <svg width="26" height="26" viewBox="0 0 22 22" className="totp-ring -rotate-90" role="img" aria-label={`${code.remaining} seconds remaining`}>
        <circle cx="11" cy="11" r="9" fill="none" stroke="var(--border)" strokeWidth="2" />
        <circle cx="11" cy="11" r="9" fill="none" stroke={code.remaining <= 5 ? "var(--warning)" : "var(--silver-strong)"} strokeWidth="2" strokeDasharray={c} strokeDashoffset={c * (1 - code.remaining / code.period)} />
      </svg>
      <span className="w-6 text-right text-[12px] tabular-nums text-muted">{code.remaining}s</span>
      <IconButton label="Copy one-time code" onClick={() => void copyText(code.code, "Code", { ...ctx, kind: "totp_copy" })} data-testid="totp-copy">
        <Copy aria-hidden />
      </IconButton>
    </div>
  );
}
