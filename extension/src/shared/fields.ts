/**
 * Form field detection heuristics. Pure DOM functions (unit-tested with jsdom).
 */

import type { FieldKind, FormKind } from "./messages";

const NEW_HINT = /new|confirm|create|register|sign.?up|repeat|retype|verify.?pass|again/i;
const CURRENT_HINT = /current|old|existing/i;
const USER_HINT = /user|e-?mail|login|account|identifier|ident|nickname|uname|member/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification.?code|verify.?code|auth.?code|security.?code|two.?factor|token|pin.?code|sms.?code/i;
const SKIP_HINT = /search|captcha|coupon|promo|zip|postal|query/i;

function hints(el: HTMLInputElement): string {
  return [el.name, el.id, el.placeholder, el.getAttribute("aria-label") ?? "", el.className]
    .filter(Boolean)
    .join(" ");
}

function autocompleteTokens(el: HTMLInputElement): string[] {
  return (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
}

export function classifyInput(el: HTMLInputElement): FieldKind | null {
  const type = (el.getAttribute("type") ?? "text").toLowerCase();
  const ac = autocompleteTokens(el);
  const h = hints(el);

  if (ac.includes("one-time-code")) return "otp";
  if (type === "password") {
    if (ac.includes("new-password")) return "new-password";
    if (ac.includes("current-password")) return "current-password";
    if (CURRENT_HINT.test(h)) return "current-password";
    if (NEW_HINT.test(h)) return "new-password";
    return "password";
  }
  if (!["text", "email", "tel", "number", ""].includes(type)) return null;
  if (SKIP_HINT.test(h)) return null;
  if (ac.includes("username") || ac.includes("email") || ac.includes("webauthn")) return "username";
  if (OTP_HINT.test(h)) {
    const max = Number(el.getAttribute("maxlength") ?? "0");
    const numeric = el.inputMode === "numeric" || type === "number" || type === "tel" || /\d/.test(el.getAttribute("pattern") ?? "");
    if ((max >= 1 && max <= 8) || numeric) return "otp";
  }
  if (type === "email") return "username";
  if (USER_HINT.test(h)) return "username";
  return null;
}

/** Visible, enabled, writable, not hidden by opacity on itself or ancestors. */
export function isFillable(el: HTMLInputElement, win: Window = window): boolean {
  if (el.disabled || el.readOnly) return false;
  if ((el.getAttribute("type") ?? "").toLowerCase() === "hidden") return false;
  let node: Element | null = el;
  while (node) {
    const cs = win.getComputedStyle(node);
    if (cs.display === "none" || cs.visibility === "hidden" || cs.visibility === "collapse") return false;
    if (parseFloat(cs.opacity || "1") < 0.1) return false;
    node = node.parentElement;
  }
  const r = el.getBoundingClientRect();
  if (r.width < 4 || r.height < 4) return false;
  // Pushed far off-screen.
  if (r.right < -1000 || r.bottom < -1000 || r.left > 20000 || r.top > 50000) return false;
  return true;
}

export interface FieldGroup {
  root: HTMLFormElement | Document;
  username: HTMLInputElement | null;
  passwords: { el: HTMLInputElement; kind: FieldKind }[];
  otp: HTMLInputElement[];
  kind: FormKind;
}

function inputsIn(root: ParentNode): HTMLInputElement[] {
  return Array.from(root.querySelectorAll("input"));
}

/** Group fields by form (or the whole document for formless pages). */
export function findGroups(doc: Document, fillable: (el: HTMLInputElement) => boolean = (el) => isFillable(el, doc.defaultView ?? window)): FieldGroup[] {
  const roots: (HTMLFormElement | Document)[] = [...Array.from(doc.forms)];
  const formless = inputsIn(doc).filter((i) => !i.form);
  if (formless.length) roots.push(doc);
  const groups: FieldGroup[] = [];
  for (const root of roots) {
    const inputs = (root === doc ? formless : inputsIn(root as HTMLFormElement)).filter(fillable);
    const passwords: FieldGroup["passwords"] = [];
    const otp: HTMLInputElement[] = [];
    let username: HTMLInputElement | null = null;
    const usernameCandidates: HTMLInputElement[] = [];
    for (const el of inputs) {
      const k = classifyInput(el);
      if (k === "otp") otp.push(el);
      else if (k === "username") usernameCandidates.push(el);
      else if (k) passwords.push({ el, kind: k });
    }
    if (passwords.length) {
      // Prefer the username candidate that precedes the first password field.
      const first = passwords[0].el;
      const before = usernameCandidates.filter((u) => u.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING);
      username = before[before.length - 1] ?? usernameCandidates[0] ?? null;
      if (!username) {
        // Fall back: the nearest preceding plain text input.
        const texts = inputs.filter(
          (i) => ["text", "email", "", "tel"].includes((i.getAttribute("type") ?? "text").toLowerCase()) &&
            i.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING &&
            !SKIP_HINT.test(hints(i)),
        );
        username = texts[texts.length - 1] ?? null;
      }
    } else {
      username = usernameCandidates[0] ?? null;
    }
    if (!passwords.length && !otp.length && !username) continue;
    groups.push({ root, username, passwords, otp, kind: formKind(passwords, otp) });
  }
  return groups;
}

export function formKind(passwords: { kind: FieldKind }[], otp: HTMLInputElement[]): FormKind {
  if (!passwords.length && otp.length) return "otp";
  const kinds = passwords.map((p) => p.kind);
  if (kinds.includes("current-password") && kinds.some((k) => k === "new-password" || k === "password")) return "change";
  if (passwords.length >= 3) return "change";
  if (kinds.includes("new-password") || passwords.length === 2) return "signup";
  return "login";
}

/** The password value to save from a submitted group (new password on change/signup forms). */
export function capturedPassword(g: FieldGroup): string {
  const byKind = (k: FieldKind) => g.passwords.find((p) => p.kind === k && p.el.value)?.el.value;
  if (g.kind === "change") {
    const news = g.passwords.filter((p) => p.kind !== "current-password" && p.el.value);
    return news[0]?.el.value ?? "";
  }
  return byKind("new-password") ?? byKind("password") ?? byKind("current-password") ?? g.passwords.find((p) => p.el.value)?.el.value ?? "";
}

/** Set a value the way frameworks (React/Vue) observe it. */
export function setFieldValue(el: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(el) as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set ?? Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  el.focus();
  setter ? setter.call(el, value) : (el.value = value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Fill a one-time code into one field, or across split single-digit fields. */
export function fillOtp(fields: HTMLInputElement[], code: string): void {
  if (fields.length >= code.length && fields.every((f) => Number(f.getAttribute("maxlength") ?? "0") === 1)) {
    code.split("").forEach((c, i) => setFieldValue(fields[i], c));
  } else if (fields[0]) {
    setFieldValue(fields[0], code);
  }
}
