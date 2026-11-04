import { useSyncExternalStore } from "react";

export interface Toast {
  id: number;
  tone: "neutral" | "success" | "danger";
  text: string;
}

let toasts: Toast[] = [];
let next = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function push(tone: Toast["tone"], text: string, ms = 4000) {
  const id = next++;
  toasts = [...toasts, { id, tone, text }];
  emit();
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id);
    emit();
  }, ms);
}

export const toast = {
  info: (t: string) => push("neutral", t),
  success: (t: string) => push("success", t),
  error: (t: string) => push("danger", t, 6000),
};

export function useToasts(): Toast[] {
  return useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => toasts,
  );
}
