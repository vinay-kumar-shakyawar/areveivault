import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import type { ItemSummary, VaultSummary } from "@arevei/client";
import { Avatar } from "@arevei/ui";
import { engine } from "../lib/app";
import { TYPES } from "../lib/itemTypes";

/** Cmd/Ctrl+K search across the decrypted in-memory index (inside the engine). */
export function CommandPalette({ open, onClose, onPick }: { open: boolean; onClose: () => void; onPick: (id: string) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [q, setQ] = useState("");
  const [results, setResults] = useState<ItemSummary[]>([]);
  const [vaults, setVaults] = useState<Map<string, string>>(new Map());
  const [active, setActive] = useState(0);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      setQ("");
      void engine.call<{ vaults: VaultSummary[] }>("list_vaults").then((r) => setVaults(new Map(r.vaults.map((v) => [v.id, v.client_name ? `${v.client_name} / ${v.name}` : v.name]))));
    }
    if (!open && d.open) d.close();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let live = true;
    void engine.call<ItemSummary[]>("list_items", { query: q }).then((r) => {
      if (live) {
        setResults(r.slice(0, 50));
        setActive(0);
      }
    });
    return () => {
      live = false;
    };
  }, [q, open]);

  const pick = (id: string) => {
    onPick(id);
    onClose();
  };

  return (
    <dialog
      ref={ref}
      className="av-modal mt-[12vh] self-start"
      aria-label="Search vault"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => e.target === ref.current && onClose()}
      data-testid="command-palette"
    >
      {open ? (
        <div>
          <div className="flex items-center gap-2 border-b border-line px-4">
            <Search className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
            <input
              autoFocus
              className="h-12 flex-1 bg-transparent text-[15px] outline-none"
              placeholder="Search items, clients, projects, tags…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActive((a) => Math.min(a + 1, results.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActive((a) => Math.max(a - 1, 0));
                } else if (e.key === "Enter" && results[active]) {
                  pick(results[active].id);
                }
              }}
              aria-label="Search"
              aria-controls="palette-results"
              aria-activedescendant={results[active] ? `pr-${results[active].id}` : undefined}
              data-testid="palette-input"
            />
            <kbd className="rounded-sm border border-line px-1.5 text-[11px] text-muted">Esc</kbd>
          </div>
          <ul id="palette-results" role="listbox" className="max-h-[50vh] overflow-y-auto py-1">
            {results.length === 0 ? <li className="px-4 py-8 text-center text-[13px] text-muted">No results</li> : null}
            {results.map((r, i) => {
              const T = TYPES[r.type] ?? TYPES.secure_note;
              return (
                <li
                  key={r.id}
                  id={`pr-${r.id}`}
                  role="option"
                  aria-selected={i === active}
                  className={`mx-1 flex cursor-pointer items-center gap-3 rounded-sm px-3 py-2 ${i === active ? "bg-raised" : ""}`}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => pick(r.id)}
                  data-testid="palette-result"
                >
                  <Avatar name={r.title} size={28} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-medium">{r.title}</div>
                    <div className="truncate text-[12px] text-muted">
                      {r.subtitle ? `${r.subtitle} · ` : ""}
                      {vaults.get(r.vault_id) ?? ""}
                    </div>
                  </div>
                  <T.icon className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}
    </dialog>
  );
}
