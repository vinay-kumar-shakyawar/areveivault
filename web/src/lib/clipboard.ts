/**
 * Copy with timed auto-clear (architecture §12.2). Browsers only let a focused
 * page write the clipboard, so if the timer fires while unfocused we clear on the
 * next focus. OS clipboard history may still keep a copy — the UI says so.
 */

export interface ClipboardDeps {
  write: (text: string) => Promise<void>;
  hasFocus: () => boolean;
  onFocus: (fn: () => void) => () => void;
  setTimer: (fn: () => void, ms: number) => unknown;
  clearTimer: (t: unknown) => void;
  now: () => number;
}

export interface ClipboardState {
  label: string | null;
  expiresAt: number | null;
  pendingClear: boolean;
}

export class ClipboardManager {
  private timer: unknown = null;
  private unfocus: (() => void) | null = null;
  private state: ClipboardState = { label: null, expiresAt: null, pendingClear: false };
  private listeners = new Set<(s: ClipboardState) => void>();

  constructor(private deps: ClipboardDeps) {}

  getState = () => this.state;

  subscribe(fn: (s: ClipboardState) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private set(s: ClipboardState) {
    this.state = s;
    this.listeners.forEach((l) => l(s));
  }

  async copy(text: string, label: string, seconds: number): Promise<void> {
    await this.deps.write(text);
    this.reset();
    if (seconds <= 0) {
      this.set({ label, expiresAt: null, pendingClear: false });
      return;
    }
    this.set({ label, expiresAt: this.deps.now() + seconds * 1000, pendingClear: false });
    this.timer = this.deps.setTimer(() => void this.clear(), seconds * 1000);
  }

  /** Clears now if focused, else defers to the next focus event. */
  async clear(): Promise<void> {
    this.timer = null;
    if (this.deps.hasFocus()) {
      try {
        await this.deps.write("");
      } catch {
        /* lost focus between check and write */
      }
      this.unfocus?.();
      this.unfocus = null;
      this.set({ label: null, expiresAt: null, pendingClear: false });
      return;
    }
    this.set({ ...this.state, expiresAt: null, pendingClear: true });
    if (!this.unfocus) {
      this.unfocus = this.deps.onFocus(() => void this.clear());
    }
  }

  private reset() {
    if (this.timer !== null) this.deps.clearTimer(this.timer);
    this.timer = null;
    this.unfocus?.();
    this.unfocus = null;
  }

  dispose() {
    this.reset();
    this.listeners.clear();
  }
}

export function browserClipboardDeps(): ClipboardDeps {
  return {
    write: (t) => navigator.clipboard.writeText(t),
    hasFocus: () => document.hasFocus(),
    onFocus: (fn) => {
      window.addEventListener("focus", fn);
      return () => window.removeEventListener("focus", fn);
    },
    setTimer: (fn, ms) => setTimeout(fn, ms),
    clearTimer: (t) => clearTimeout(t as ReturnType<typeof setTimeout>),
    now: () => Date.now(),
  };
}
