import { useEffect, useState } from "react";
import { ClipboardCheck, ClipboardX } from "lucide-react";
import { Status } from "@arevei/ui";
import { clipboard } from "../lib/app";
import { useNow } from "../lib/hooks";
import { settings } from "../lib/settings";
import { useToasts } from "../lib/toast";

/** Toasts + the clipboard auto-clear countdown. */
export function Toaster() {
  const toasts = useToasts();
  const [clip, setClip] = useState(clipboard.getState());
  useEffect(() => clipboard.subscribe(setClip), []);
  const now = useNow(500);
  const remaining = clip.expiresAt ? Math.max(0, Math.ceil((clip.expiresAt - now) / 1000)) : null;

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(360px,calc(100vw-32px))] flex-col gap-2" aria-live="polite">
      {clip.label ? (
        <div className="pointer-events-auto flex items-center gap-3 rounded border border-line bg-surface px-4 py-3 shadow-modal" data-testid="clipboard-toast">
          {clip.pendingClear ? (
            <ClipboardX className="h-4 w-4 text-warning" strokeWidth={1.5} aria-hidden />
          ) : (
            <ClipboardCheck className="h-4 w-4 text-silver-strong" strokeWidth={1.5} aria-hidden />
          )}
          <div className="min-w-0 flex-1 text-[13px]">
            <div className="font-medium">{clip.label} copied</div>
            <div className="text-muted">
              {clip.pendingClear
                ? "Return to this tab to clear the clipboard."
                : remaining !== null
                  ? `Clipboard clears in ${remaining}s. OS clipboard history may keep a copy.`
                  : "Auto-clear is off."}
            </div>
          </div>
          {remaining !== null ? (
            <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden className="flex-none -rotate-90">
              <circle cx="11" cy="11" r="9" fill="none" stroke="var(--border)" strokeWidth="2" />
              <circle
                cx="11"
                cy="11"
                r="9"
                fill="none"
                stroke="var(--silver-strong)"
                strokeWidth="2"
                strokeDasharray={56.5}
                strokeDashoffset={56.5 * (1 - remaining / Math.max(1, settings.get().clipboardSeconds))}
              />
            </svg>
          ) : null}
        </div>
      ) : null}
      {toasts.map((t) => (
        <div key={t.id} className="pointer-events-auto rounded border border-line bg-surface px-4 py-3 text-[13px] shadow-modal" role={t.tone === "danger" ? "alert" : "status"}>
          {t.tone === "neutral" ? t.text : <Status tone={t.tone}>{t.text}</Status>}
        </div>
      ))}
    </div>
  );
}
