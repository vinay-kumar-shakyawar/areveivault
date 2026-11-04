/**
 * Arevei Vault shared UI primitives (web app + extension). Styling lives in
 * ui.css + tokens.css; no runtime style injection, so they work under a strict CSP.
 */
import {
  forwardRef,
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X } from "lucide-react";

export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");

// ---------- Button ----------
type ButtonVariant = "default" | "primary" | "danger" | "ghost";
export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "md" | "sm";
  block?: boolean;
  loading?: boolean;
}
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "default", size = "md", block, loading, className, children, disabled, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cx(
        "av-btn",
        variant !== "default" && `av-btn--${variant}`,
        size === "sm" && "av-btn--sm",
        block && "av-btn--block",
        className,
      )}
      {...rest}
    >
      {loading ? <span className="av-spinner" aria-hidden /> : null}
      {children}
    </button>
  );
});

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
  active?: boolean;
}
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, active, className, children, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      className={cx("av-icon-btn", active && "is-active", className)}
      {...rest}
    >
      {children}
    </button>
  );
});

// ---------- Fields ----------
export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="av-field">
      <label className="av-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <span className="av-error-text" role="alert">
          <AlertTriangle size={14} strokeWidth={1.75} aria-hidden />
          {error}
        </span>
      ) : hint ? (
        <span className="av-hint">{hint}</span>
      ) : null}
    </div>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }>(
  function Input({ className, mono, ...rest }, ref) {
    return <input ref={ref} className={cx("av-input", mono && "av-input--mono", className)} {...rest} />;
  },
);

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }
>(function Textarea({ className, mono, ...rest }, ref) {
  return <textarea ref={ref} className={cx("av-textarea", mono && "av-textarea--mono", className)} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, ...rest },
  ref,
) {
  return <select ref={ref} className={cx("av-select", className)} {...rest} />;
});

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
  ...rest
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
  "data-testid"?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className="av-toggle"
      onClick={() => onChange(!checked)}
      {...rest}
    />
  );
}

// ---------- Modal (native <dialog>: focus trap + Esc without injected styles) ----------
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  wide,
  testId,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  testId?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      if (typeof d.showModal === "function") d.showModal();
      else d.setAttribute("open", "");
    }
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={cx("av-modal", wide && "av-modal--wide")}
      aria-labelledby={titleId}
      data-testid={testId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      {open ? (
        <>
          <div className="av-modal__head">
            <h2 className="av-modal__title" id={titleId}>
              {title}
            </h2>
            <IconButton label="Close" onClick={onClose}>
              <X aria-hidden />
            </IconButton>
          </div>
          <div className="av-modal__body">{children}</div>
          {footer ? <div className="av-modal__foot">{footer}</div> : null}
        </>
      ) : null}
    </dialog>
  );
}

// ---------- Status (color is never the only signal: icon + text always) ----------
export function Status({ tone, children }: { tone: "danger" | "warning" | "success" | "neutral"; children: ReactNode }) {
  const Icon = tone === "danger" ? ShieldAlert : tone === "warning" ? AlertTriangle : tone === "success" ? CheckCircle2 : Info;
  return (
    <span className={`av-status av-status--${tone}`}>
      <Icon aria-hidden />
      {children}
    </span>
  );
}

export function Badge({ children }: { children: ReactNode }) {
  return <span className="av-badge">{children}</span>;
}

export function initials(name: string): string {
  const words = name
    .replace(/https?:\/\//, "")
    .split(/[\s._@\-/]+/)
    .filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 2);
  return (words[0][0] + words[1][0]).toUpperCase();
}

/** Monochrome initials avatar — never colored circles (brand rule). */
export function Avatar({ name, size = 32 }: { name: string; size?: number }) {
  return (
    <span
      className="av-avatar"
      aria-hidden
      style={{ width: size, height: size, fontSize: Math.round(size * 0.38) }}
    >
      {initials(name)}
    </span>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <span className="av-spinner" role="status" aria-label={label} />;
}

export function StrengthMeter({ score }: { score: number }) {
  return (
    <div className="av-meter" data-score={score} aria-hidden>
      <span />
      <span />
      <span />
      <span />
    </div>
  );
}

// ---------- Password rendering ----------
export interface CharRun {
  kind: "letter" | "digit" | "symbol";
  text: string;
}

/** Renders a revealed secret with digits/symbols in --silver-strong (brand rule). */
export function SecretText({ runs, testId }: { runs: CharRun[]; testId?: string }) {
  return (
    <span className="av-secret" data-testid={testId}>
      {runs.map((r, i) => (
        <span key={i} className={`ch-${r.kind}`}>
          {r.text}
        </span>
      ))}
    </span>
  );
}

/** Client-side tokenizer matching core's `generator::tokenize` (for UIs without the engine). */
export function tokenize(s: string): CharRun[] {
  const out: CharRun[] = [];
  for (const ch of s) {
    const kind: CharRun["kind"] = /\p{L}/u.test(ch) ? "letter" : /[0-9]/.test(ch) ? "digit" : "symbol";
    const last = out[out.length - 1];
    if (last && last.kind === kind) last.text += ch;
    else out.push({ kind, text: ch });
  }
  return out;
}

// ---------- Logo ----------
/** Shield + keyhole mark. Silver gradient on dark, solid black on light (via --logo-fill). */
export function LogoMark({ size = 28, gradient }: { size?: number; gradient?: boolean }) {
  const id = useId().replace(/:/g, "");
  const fill = gradient ? `url(#${id})` : "currentColor";
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className={cx("av-logo-mark", gradient && "av-logo-mark--g")}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#e8e8e8" />
          <stop offset=".5" stopColor="#a8a9ad" />
          <stop offset="1" stopColor="#d4d4d4" />
        </linearGradient>
      </defs>
      <path
        className="av-logo-s"
        d="M16 3.5l10.5 4v7.9c0 6.5-4.4 11.3-10.5 13.6C9.9 26.7 5.5 21.9 5.5 15.4V7.5z"
        fill="none"
        stroke={fill}
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <circle className="av-logo-f" cx="16" cy="14" r="2.8" fill={fill} />
      <path className="av-logo-f" d="M14.7 16h2.6l.9 5.4h-4.4z" fill={fill} />
    </svg>
  );
}

export function Logo({ size = 28, gradient }: { size?: number; gradient?: boolean }) {
  return (
    <span className="av-logo" aria-label="Arevei Vault">
      <LogoMark size={size} gradient={gradient} />
      <span className="av-logo-word">
        Arevei <span className="av-logo-word-light">Vault</span>
      </span>
    </span>
  );
}
