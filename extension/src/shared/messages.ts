/**
 * Message schemas between contexts, with strict validation. Content scripts run
 * in pages we don't trust, so every inbound message is shape- and size-checked.
 * Page URL/origin/frame are NEVER part of a content-script message: the service
 * worker takes them from `chrome.runtime.MessageSender`.
 */

export type FieldKind = "username" | "password" | "new-password" | "current-password" | "otp";
export type FormKind = "login" | "signup" | "change" | "otp";

export type ContentMessage =
  | { type: "cs:hello" }
  | { type: "cs:open-menu"; field: FieldKind; formKind: FormKind }
  | { type: "cs:shortcut-fill"; field: FieldKind; formKind: FormKind }
  | { type: "cs:menu-visibility"; token: string; visible: boolean }
  | { type: "cs:capture"; username: string; password: string; formKind: FormKind }
  | { type: "cs:close-menu"; token: string };

export type MenuPortMessage =
  | { type: "menu:init"; token: string }
  | { type: "menu:select"; token: string; itemId: string; confirmInsecure: boolean; visible: boolean }
  | { type: "menu:generate"; token: string; visible: boolean }
  | { type: "menu:close"; token: string };

export type PromptPortMessage =
  | { type: "prompt:init"; token: string }
  | { type: "prompt:save"; token: string; vaultId: string; title: string; visible: boolean }
  | { type: "prompt:update"; token: string; visible: boolean }
  | { type: "prompt:never"; token: string }
  | { type: "prompt:dismiss"; token: string };

export type ExternalMessage = { type: "locked" } | { type: "unlocked" } | { type: "lock-now" } | { type: "verify-build" };

const FIELD_KINDS: FieldKind[] = ["username", "password", "new-password", "current-password", "otp"];
const FORM_KINDS: FormKind[] = ["login", "signup", "change", "otp"];
export const MAX_SECRET_LEN = 1024;
export const MAX_USERNAME_LEN = 512;
const TOKEN_RE = /^[A-Za-z0-9_-]{16,64}$/;
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;

const isObj = (m: unknown): m is Record<string, unknown> => typeof m === "object" && m !== null && !Array.isArray(m);
const str = (v: unknown, max: number) => typeof v === "string" && v.length <= max;
const token = (v: unknown) => typeof v === "string" && TOKEN_RE.test(v);
const bool = (v: unknown) => typeof v === "boolean";

function exactKeys(m: Record<string, unknown>, keys: string[]): boolean {
  const k = Object.keys(m);
  return k.length === keys.length && k.every((x) => keys.includes(x));
}

export function validateContentMessage(m: unknown): ContentMessage | null {
  if (!isObj(m) || typeof m.type !== "string") return null;
  switch (m.type) {
    case "cs:hello":
      return exactKeys(m, ["type"]) ? (m as ContentMessage) : null;
    case "cs:open-menu":
    case "cs:shortcut-fill":
      return exactKeys(m, ["type", "field", "formKind"]) &&
        FIELD_KINDS.includes(m.field as FieldKind) &&
        FORM_KINDS.includes(m.formKind as FormKind)
        ? (m as ContentMessage)
        : null;
    case "cs:menu-visibility":
      return exactKeys(m, ["type", "token", "visible"]) && token(m.token) && bool(m.visible) ? (m as ContentMessage) : null;
    case "cs:capture":
      return exactKeys(m, ["type", "username", "password", "formKind"]) &&
        str(m.username, MAX_USERNAME_LEN) &&
        str(m.password, MAX_SECRET_LEN) &&
        (m.password as string).length > 0 &&
        FORM_KINDS.includes(m.formKind as FormKind)
        ? (m as ContentMessage)
        : null;
    case "cs:close-menu":
      return exactKeys(m, ["type", "token"]) && token(m.token) ? (m as ContentMessage) : null;
    default:
      return null;
  }
}

export function validateMenuMessage(m: unknown): MenuPortMessage | null {
  if (!isObj(m) || !token(m.token)) return null;
  switch (m.type) {
    case "menu:init":
    case "menu:close":
      return exactKeys(m, ["type", "token"]) ? (m as MenuPortMessage) : null;
    case "menu:select":
      return exactKeys(m, ["type", "token", "itemId", "confirmInsecure", "visible"]) &&
        typeof m.itemId === "string" &&
        ID_RE.test(m.itemId) &&
        bool(m.confirmInsecure) &&
        bool(m.visible)
        ? (m as MenuPortMessage)
        : null;
    case "menu:generate":
      return exactKeys(m, ["type", "token", "visible"]) && bool(m.visible) ? (m as MenuPortMessage) : null;
    default:
      return null;
  }
}

export function validatePromptMessage(m: unknown): PromptPortMessage | null {
  if (!isObj(m) || !token(m.token)) return null;
  switch (m.type) {
    case "prompt:init":
    case "prompt:never":
    case "prompt:dismiss":
      return exactKeys(m, ["type", "token"]) ? (m as PromptPortMessage) : null;
    case "prompt:save":
      return exactKeys(m, ["type", "token", "vaultId", "title", "visible"]) &&
        typeof m.vaultId === "string" &&
        ID_RE.test(m.vaultId) &&
        str(m.title, 512) &&
        bool(m.visible)
        ? (m as PromptPortMessage)
        : null;
    case "prompt:update":
      return exactKeys(m, ["type", "token", "visible"]) && bool(m.visible) ? (m as PromptPortMessage) : null;
    default:
      return null;
  }
}

/** Messages from the vault web app (externally_connectable). Lock-state only, never keys. */
export function validateExternalMessage(m: unknown): ExternalMessage | null {
  if (!isObj(m) || !exactKeys(m, ["type"])) return null;
  return ["locked", "unlocked", "lock-now", "verify-build"].includes(m.type as string) ? (m as ExternalMessage) : null;
}

export function randomToken(): string {
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
