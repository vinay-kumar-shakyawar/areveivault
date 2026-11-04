/**
 * Content script (isolated world, all frames). Detects fields, draws the inline
 * icon, hosts the extension-origin menu/prompt iframes inside closed shadow roots,
 * fills only what the service worker sends for THIS frame, and captures
 * submitted credentials. It never sees vault data otherwise.
 */

import { capturedPassword, classifyInput, fillOtp, findGroups, isFillable, setFieldValue, type FieldGroup } from "../shared/fields";
import type { FieldKind } from "../shared/messages";

const ICON_SIZE = 20;
const icons = new Map<HTMLInputElement, HTMLDivElement>();
let groups: FieldGroup[] = [];
let activeField: HTMLInputElement | null = null;
let menu: { host: HTMLDivElement; token: string; field: HTMLInputElement; timer: number } | null = null;
let prompt: HTMLDivElement | null = null;
let lastCreds: { username: string; password: string; field: HTMLInputElement; ts: number; group: FieldGroup } | null = null;
let lastUsername = "";

const send = <T = any>(msg: unknown): Promise<T> => chrome.runtime.sendMessage(msg) as Promise<T>;

function groupOf(el: HTMLInputElement): FieldGroup | undefined {
  return groups.find((g) => g.username === el || g.passwords.some((p) => p.el === el) || g.otp.includes(el));
}

function fieldKindOf(el: HTMLInputElement): FieldKind {
  return classifyInput(el) ?? "username";
}

// ------------------------------------------------------------------ inline icon

const ICON_SVG = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="2"/><path d="M12 13v3"/></svg>`;

function makeHost(): HTMLDivElement {
  const host = document.createElement("div");
  host.style.cssText = "all: initial; position: absolute; z-index: 2147483647; width: 0; height: 0;";
  return host;
}

function attachIcon(field: HTMLInputElement) {
  if (icons.has(field)) return;
  const host = makeHost();
  host.setAttribute("data-arevei-icon", "");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    button{all:initial;box-sizing:border-box;position:absolute;width:${ICON_SIZE}px;height:${ICON_SIZE}px;display:flex;align-items:center;justify-content:center;
      border-radius:6px;cursor:pointer;color:#a3a3a3;background:#141414;border:1px solid #2a2a2a;}
    button:hover{color:#c0c0c0;border-color:#6b6b6b}
    button:focus-visible{outline:2px solid #c0c0c0;outline-offset:1px}
  </style><button type="button" title="Arevei Vault" aria-label="Open Arevei Vault autofill">${ICON_SVG}</button>`;
  const btn = root.querySelector("button")!;
  btn.addEventListener("mousedown", (e) => e.preventDefault());
  btn.addEventListener("click", (e) => {
    // Only real user clicks open the menu; page scripts can't synthesize trusted events.
    if (!e.isTrusted) return;
    e.preventDefault();
    e.stopPropagation();
    void openMenu(field);
  });
  (document.body ?? document.documentElement).appendChild(host);
  icons.set(field, host);
  positionIcon(field, host);
}

function positionIcon(field: HTMLInputElement, host: HTMLDivElement) {
  if (!field.isConnected || !isFillable(field)) {
    host.style.display = "none";
    return;
  }
  const r = field.getBoundingClientRect();
  host.style.display = "block";
  host.style.left = `${r.right + window.scrollX - ICON_SIZE - 6}px`;
  host.style.top = `${r.top + window.scrollY + (r.height - ICON_SIZE) / 2}px`;
}

let rafPending = false;
function repositionAll() {
  if (rafPending) return;
  rafPending = true;
  requestAnimationFrame(() => {
    rafPending = false;
    for (const [f, h] of icons) {
      if (!f.isConnected) {
        h.remove();
        icons.delete(f);
      } else positionIcon(f, h);
    }
    if (menu) positionMenu(menu.host, menu.field);
  });
}

// ------------------------------------------------------------------ scanning

function scan() {
  groups = findGroups(document);
  for (const g of groups) {
    // A lone username/email field (newsletter boxes etc.) gets an icon only when explicitly marked as a login field.
    const loginish = g.passwords.length > 0 || /\b(username|webauthn)\b/.test(g.username?.getAttribute("autocomplete") ?? "");
    const fields = [loginish ? g.username : null, ...g.passwords.map((p) => p.el), ...g.otp].filter(Boolean) as HTMLInputElement[];
    for (const f of fields) {
      attachIcon(f);
      if (!(f as any).__areveiBound) {
        (f as any).__areveiBound = true;
        f.addEventListener("input", () => onFieldInput(f));
        f.addEventListener("focus", () => (activeField = f));
        f.addEventListener("keydown", (e) => {
          if (e.key === "Enter" && e.isTrusted) captureGroup(groupOf(f));
        });
      }
    }
  }
}

function onFieldInput(f: HTMLInputElement) {
  const g = groupOf(f);
  if (!g) return;
  if (g.username === f) lastUsername = f.value;
  const pw = capturedPassword(g);
  if (pw) lastCreds = { username: g.username?.value || lastUsername, password: pw, field: g.passwords[0]?.el ?? f, ts: Date.now(), group: g };
}

let scanTimer: number | undefined;
const observer = new MutationObserver(() => {
  clearTimeout(scanTimer);
  scanTimer = window.setTimeout(() => {
    checkSpaSubmit();
    scan();
    repositionAll();
  }, 250);
});

// ------------------------------------------------------------------ menu

function positionMenu(host: HTMLDivElement, field: HTMLInputElement) {
  const r = field.getBoundingClientRect();
  host.style.position = "fixed";
  host.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - 328))}px`;
  host.style.top = `${Math.min(r.bottom + 4, window.innerHeight - 290)}px`;
}

async function openMenu(field: HTMLInputElement, existingToken?: string) {
  closeMenu();
  const g = groupOf(field);
  let token = existingToken;
  if (!token) {
    const r = await send<{ token?: string; error?: string }>({ type: "cs:open-menu", field: fieldKindOf(field), formKind: g?.kind ?? "login" });
    if (!r?.token) return;
    token = r.token;
  }
  const host = makeHost();
  host.setAttribute("data-arevei-menu", "");
  const root = host.attachShadow({ mode: "closed" });
  const iframe = document.createElement("iframe");
  iframe.src = `${chrome.runtime.getURL("menu.html")}#${token}`;
  iframe.style.cssText =
    "all: initial; display: block; width: 320px; height: 280px; border: 0; border-radius: 12px; color-scheme: normal; box-shadow: 0 16px 48px rgb(0 0 0 / .45); opacity: 1;";
  iframe.setAttribute("title", "Arevei Vault");
  root.appendChild(iframe);
  (document.body ?? document.documentElement).appendChild(host);
  positionMenu(host, field);
  activeField = field;
  const timer = window.setInterval(() => reportVisibility(), 250);
  menu = { host, token, field, timer };
  reportVisibility();
}

/** Page-side clickjacking checks: our host must be the topmost element and fully opaque. */
let lastVisible: boolean | null = null;
function reportVisibility() {
  if (!menu) return;
  const r = menu.host.getBoundingClientRect();
  const pts: [number, number][] = [
    [r.left + 160, r.top + 140],
    [r.left + 20, r.top + 20],
    [r.left + 300, r.top + 260],
  ];
  let visible = pts.every(([x, y]) => {
    const el = document.elementFromPoint(x, y);
    return el === menu!.host;
  });
  for (const el of [document.documentElement, document.body, menu.host]) {
    if (!el) continue;
    const cs = getComputedStyle(el);
    if (parseFloat(cs.opacity) < 1 || cs.visibility !== "visible" || (cs.filter && cs.filter !== "none")) visible = false;
  }
  if (visible !== lastVisible) {
    lastVisible = visible;
    void send({ type: "cs:menu-visibility", token: menu.token, visible });
  }
}

function closeMenu() {
  if (!menu) return;
  clearInterval(menu.timer);
  void send({ type: "cs:close-menu", token: menu.token }).catch(() => {});
  menu.host.remove();
  menu = null;
  lastVisible = null;
}

document.addEventListener(
  "mousedown",
  (e) => {
    if (menu && e.target !== menu.host && !icons.has(e.target as HTMLInputElement)) {
      const path = e.composedPath();
      if (!path.includes(menu.host) && ![...icons.values()].some((h) => path.includes(h))) closeMenu();
    }
  },
  true,
);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeMenu();
  }
});

// ------------------------------------------------------------------ prompt

function showPrompt(token: string) {
  if (window.top !== window) return;
  prompt?.remove();
  const host = makeHost();
  host.setAttribute("data-arevei-prompt", "");
  host.style.position = "fixed";
  host.style.top = "16px";
  host.style.right = "16px";
  host.style.left = "auto";
  const root = host.attachShadow({ mode: "closed" });
  const iframe = document.createElement("iframe");
  iframe.src = `${chrome.runtime.getURL("prompt.html")}#${token}`;
  iframe.style.cssText =
    "all: initial; display: block; width: 360px; height: 300px; border: 0; border-radius: 12px; color-scheme: normal; box-shadow: 0 16px 48px rgb(0 0 0 / .45);";
  iframe.setAttribute("title", "Arevei Vault — save login");
  root.appendChild(iframe);
  host.style.width = "360px";
  (document.body ?? document.documentElement).appendChild(host);
  prompt = host;
}

// ------------------------------------------------------------------ capture

function captureGroup(g: FieldGroup | undefined) {
  if (!g || !g.passwords.length) return;
  const password = capturedPassword(g);
  if (!password) return;
  const username = (g.username?.value || lastUsername || "").trim();
  lastCreds = null;
  void send<{ prompt?: string }>({ type: "cs:capture", username, password, formKind: g.kind }).then((r) => {
    if (r?.prompt) showPrompt(r.prompt);
  });
}

document.addEventListener(
  "submit",
  (e) => {
    const form = e.target as HTMLFormElement;
    captureGroup(groups.find((g) => g.root === form) ?? groups.find((g) => g.passwords.some((p) => p.el.form === form)));
  },
  true,
);

document.addEventListener(
  "click",
  (e) => {
    if (!e.isTrusted) return;
    const t = (e.target as Element)?.closest?.("button, input[type=submit], input[type=button], [role=button]");
    if (!t) return;
    const text = (t.textContent || (t as HTMLInputElement).value || t.getAttribute("aria-label") || "").toLowerCase();
    const inForm = (t as HTMLButtonElement).form ?? t.closest("form");
    const g = inForm ? groups.find((x) => x.root === inForm) : groups.find((x) => x.root === document);
    if (g && (/(log|sign)\s?in|continue|next|submit|save|update|change|register|sign\s?up|create/.test(text) || (t as HTMLButtonElement).type === "submit")) {
      captureGroup(g);
    }
  },
  true,
);

/** SPA heuristic: the password field vanished shortly after the user typed credentials. */
function checkSpaSubmit() {
  if (!lastCreds || Date.now() - lastCreds.ts > 60_000) return;
  const f = lastCreds.field;
  if (!f.isConnected || !isFillable(f)) {
    const c = lastCreds;
    lastCreds = null;
    void send<{ prompt?: string }>({ type: "cs:capture", username: c.username, password: c.password, formKind: c.group.kind }).then((r) => {
      if (r?.prompt) showPrompt(r.prompt);
    });
  }
}

// ------------------------------------------------------------------ fill

function fillFromServiceWorker(m: { field: FieldKind; username: string; password: string; totp: string | null }) {
  const anchor = menu?.field ?? activeField;
  const g = (anchor && groupOf(anchor)) ?? groups.find((x) => x.passwords.length) ?? groups[0];
  closeMenu();
  if (!g) return;
  if (m.field === "otp" || (!g.passwords.length && g.otp.length)) {
    const otp = g.otp.filter((f) => isFillable(f));
    if (m.totp && otp.length) fillOtp(otp, m.totp);
    return;
  }
  if (g.username && isFillable(g.username) && m.username) setFieldValue(g.username, m.username);
  // Login forms: fill the password / current-password field, never new-password fields.
  const targets = g.passwords.filter((p) => isFillable(p.el) && (p.kind === "password" || p.kind === "current-password"));
  const target = g.kind === "change" ? targets.filter((p) => p.kind === "current-password").slice(0, 1) : targets.slice(0, 1);
  for (const p of target) setFieldValue(p.el, m.password);
  const otp = g.otp.filter((f) => isFillable(f));
  if (m.totp && otp.length) fillOtp(otp, m.totp);
}

function fillGenerated(password: string) {
  const anchor = menu?.field ?? activeField;
  const g = anchor ? groupOf(anchor) : undefined;
  closeMenu();
  const fields = g?.passwords.filter((p) => p.kind !== "current-password" && isFillable(p.el)).map((p) => p.el) ?? [];
  const targets = fields.length ? fields : anchor && isFillable(anchor) ? [anchor] : [];
  for (const f of targets) setFieldValue(f, password);
  if (g) onFieldInput(targets[0]);
}

chrome.runtime.onMessage.addListener((m, sender) => {
  if (sender.id !== chrome.runtime.id || sender.tab) return; // only the service worker
  switch (m?.type) {
    case "fill":
      fillFromServiceWorker(m);
      break;
    case "fill-generated":
      if (typeof m.password === "string") fillGenerated(m.password);
      break;
    case "close-menu":
      closeMenu();
      break;
    case "close-prompt":
      prompt?.remove();
      prompt = null;
      break;
    case "shortcut": {
      const el = document.activeElement as HTMLInputElement | null;
      if (!el || el.tagName !== "INPUT" || !groupOf(el) || !isFillable(el)) return;
      const g = groupOf(el)!;
      activeField = el;
      void send<{ token?: string; filled?: boolean }>({ type: "cs:shortcut-fill", field: fieldKindOf(el), formKind: g.kind }).then((r) => {
        if (r?.token) void openMenu(el, r.token);
      });
      break;
    }
  }
});

// ------------------------------------------------------------------ boot

function boot() {
  scan();
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class", "hidden", "type"] });
  window.addEventListener("scroll", repositionAll, true);
  window.addEventListener("resize", repositionAll);
  if (window.top === window) {
    void send<{ prompt?: string }>({ type: "cs:hello" }).then((r) => {
      if (r?.prompt) showPrompt(r.prompt);
    });
  }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
else boot();
