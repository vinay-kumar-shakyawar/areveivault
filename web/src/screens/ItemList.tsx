import { useMemo, useState } from "react";
import { Search, Star, Trash2 } from "lucide-react";
import type { ItemSummary, VaultSummary } from "@arevei/client";
import { Avatar, Input, Status } from "@arevei/ui";
import { useApp } from "../lib/app";
import { useEngine } from "../lib/hooks";
import { TYPES } from "../lib/itemTypes";
import type { View } from "../lib/nav";

export function listArgs(view: View, favorites: string[]): Record<string, unknown> {
  switch (view.k) {
    case "vault":
      return { vault_id: view.id };
    case "client":
      return { client_id: view.id };
    case "favorites":
      return { ids: favorites };
    case "tag":
      return { tag: view.tag };
    case "trash":
      return { trash: true };
    default:
      return {};
  }
}

export function viewTitle(view: View, vaults: VaultSummary[] | undefined, clients: { id: string; name: string }[] | undefined): string {
  switch (view.k) {
    case "all":
      return "All items";
    case "vault": {
      const v = vaults?.find((x) => x.id === view.id);
      return v ? (v.client_name ? `${v.client_name} / ${v.name}` : v.name) : "Vault";
    }
    case "client":
      return clients?.find((c) => c.id === view.id)?.name ?? "Client";
    case "favorites":
      return "Favorites";
    case "authenticators":
      return "Authenticators";
    case "tag":
      return `#${view.tag}`;
    case "trash":
      return "Trash";
    default:
      return "";
  }
}

export function ItemList({
  view,
  selectedId,
  onSelect,
  header,
}: {
  view: View;
  selectedId: string | null;
  onSelect: (id: string) => void;
  header: React.ReactNode;
}) {
  const { prefs } = useApp();
  const [query, setQuery] = useState("");
  const args = useMemo(() => ({ ...listArgs(view, prefs.favorites), query }), [view, prefs.favorites, query]);
  const { data, loading } = useEngine<ItemSummary[]>("list_items", args);
  let items = data ?? [];
  if (view.k === "authenticators") items = items.filter((i) => i.type === "authenticator" || i.has_totp);
  const fav = new Set(prefs.favorites);

  return (
    <div className="flex h-full flex-col">
      {header}
      <div className="border-b border-line p-3">
        <label className="relative block">
          <span className="sr-only">Filter this list</span>
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" strokeWidth={1.5} aria-hidden />
          <Input className="pl-8" placeholder="Filter" value={query} onChange={(e) => setQuery(e.target.value)} data-testid="list-filter" />
        </label>
      </div>
      {view.k === "trash" ? (
        <div className="border-b border-line px-4 py-2 text-[12px] text-muted">
          <Status tone="neutral">Items in Trash are permanently deleted after 30 days.</Status>
        </div>
      ) : null}
      <div className="min-h-0 flex-1 overflow-y-auto" role="listbox" aria-label="Items" data-testid="item-list">
        {!loading && items.length === 0 ? (
          <div className="px-6 py-16 text-center text-[13px] text-muted">{query ? "No matches." : view.k === "trash" ? "Trash is empty." : "No items yet."}</div>
        ) : null}
        {items.map((it) => {
          const T = TYPES[it.type] ?? TYPES.secure_note;
          return (
            <button
              key={it.id}
              role="option"
              aria-selected={it.id === selectedId}
              className="row-item"
              onClick={() => onSelect(it.id)}
              data-testid="item-row"
              data-item-title={it.title}
            >
              <Avatar name={it.title} size={32} />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-[13px] font-medium text-fg">{it.title}</span>
                  {fav.has(it.id) ? <Star className="h-3 w-3 flex-none text-silver-strong" strokeWidth={1.5} aria-label="Favorite" /> : null}
                </span>
                <span className="block truncate text-[12px] text-muted">{it.subtitle || it.host || T.label}</span>
              </span>
              {it.deleted_at ? <Trash2 className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden /> : <T.icon className="h-4 w-4 flex-none text-muted" strokeWidth={1.5} aria-hidden />}
            </button>
          );
        })}
      </div>
    </div>
  );
}
