/** Non-secret, per-device preferences (localStorage is fine for these). */

export interface Settings {
  theme: "system" | "dark" | "light";
  autoLockMinutes: number;
  clipboardSeconds: number;
  rememberSecretKey: boolean;
  hibpEnabled: boolean;
}

const DEFAULTS: Settings = {
  theme: "system",
  autoLockMinutes: 5,
  clipboardSeconds: 30,
  rememberSecretKey: true,
  hibpEnabled: false,
};

const KEY = "arevei-settings";
const listeners = new Set<() => void>();
let current: Settings = load();

function load(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
  } catch {
    return { ...DEFAULTS };
  }
}

export const settings = {
  get: () => current,
  update(patch: Partial<Settings>) {
    current = { ...current, ...patch };
    try {
      localStorage.setItem(KEY, JSON.stringify(current));
    } catch {
      /* storage blocked: keep in memory */
    }
    applyTheme();
    listeners.forEach((l) => l());
  },
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
};

export function applyTheme(): void {
  const t = current.theme;
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}
