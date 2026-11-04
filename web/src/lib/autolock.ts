/**
 * Inactivity auto-lock: user activity resets a timer; if the page is hidden for
 * longer than the timeout (timers are throttled in background tabs), we lock as
 * soon as it becomes visible again.
 */

export interface AutoLockOptions {
  minutes: () => number;
  onLock: () => void;
  now?: () => number;
}

const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart", "mousemove"] as const;

export function startAutoLock({ minutes, onLock, now = Date.now }: AutoLockOptions): () => void {
  let last = now();
  let timer: ReturnType<typeof setTimeout> | null = null;
  let lastMove = 0;

  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(check, Math.max(1000, minutes() * 60_000 - (now() - last)));
  };
  const check = () => {
    if (now() - last >= minutes() * 60_000) onLock();
    else schedule();
  };
  const activity = (e: Event) => {
    if (e.type === "mousemove") {
      if (now() - lastMove < 5000) return;
      lastMove = now();
    }
    last = now();
  };
  const visibility = () => {
    if (document.visibilityState === "visible") check();
  };

  ACTIVITY.forEach((t) => window.addEventListener(t, activity, { passive: true }));
  document.addEventListener("visibilitychange", visibility);
  schedule();

  return () => {
    if (timer) clearTimeout(timer);
    ACTIVITY.forEach((t) => window.removeEventListener(t, activity));
    document.removeEventListener("visibilitychange", visibility);
  };
}
