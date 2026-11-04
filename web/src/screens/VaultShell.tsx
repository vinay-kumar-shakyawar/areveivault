import { useEffect, useState } from "react";
import { AlertTriangle, Menu, Plus, RefreshCw, Search } from "lucide-react";
import type { VaultSummary } from "@arevei/client";
import { Button, IconButton } from "@arevei/ui";
import { GeneratorPanel } from "../components/Generator";
import { errorMessage, refresh, useApp } from "../lib/app";
import { useEngine } from "../lib/hooks";
import { isListView, type View } from "../lib/nav";
import { toast } from "../lib/toast";
import { AdminScreen } from "./Admin";
import { CommandPalette } from "./CommandPalette";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor, type EditorTarget } from "./ItemEditor";
import { ItemList, viewTitle } from "./ItemList";
import { SecurityScreen } from "./Security";
import { SettingsScreen } from "./Settings";
import { Sidebar } from "./Sidebar";
import { ToolsScreen } from "./Tools";

export function VaultShell() {
  const { warnings, session } = useApp();
  const { data: vl } = useEngine<{ vaults: VaultSummary[]; clients: { id: string; name: string }[] }>("list_vaults", {});
  const [view, setView] = useState<View>({ k: "all" });
  const [selected, setSelected] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorTarget | null>(null);
  const [palette, setPalette] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const navigate = (v: View) => {
    setView(v);
    setSelected(null);
    setNavOpen(false);
  };

  const doRefresh = async () => {
    setSyncing(true);
    try {
      await refresh();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setSyncing(false);
    }
  };

  const currentVault = view.k === "vault" ? vl?.vaults.find((v) => v.id === view.id) : undefined;
  const canCreate = !currentVault || currentVault.role !== "read_only";
  const list = isListView(view);

  const listHeader = (
    <div className="flex h-14 items-center gap-2 border-b border-line px-3">
      <IconButton label="Open navigation" className="lg:hidden" onClick={() => setNavOpen(true)}>
        <Menu aria-hidden />
      </IconButton>
      <h2 className="min-w-0 flex-1 truncate text-[15px] font-semibold" data-testid="view-title">
        {viewTitle(view, vl?.vaults, vl?.clients)}
      </h2>
      <IconButton label="Sync now" onClick={() => void doRefresh()} disabled={syncing} data-testid="sync-now">
        <RefreshCw aria-hidden className={syncing ? "animate-spin" : ""} />
      </IconButton>
      {view.k !== "trash" && canCreate ? (
        <Button size="sm" variant="primary" onClick={() => setEditor({ mode: "new", vaultId: currentVault?.id })} data-testid="new-item">
          <Plus aria-hidden /> New
        </Button>
      ) : null}
    </div>
  );

  let main;
  if (list) {
    main = (
      <div className="flex h-full min-w-0 flex-1">
        <div className={`h-full w-full border-r border-line lg:w-[360px] lg:flex-none ${selected ? "hidden lg:block" : ""}`}>
          <ItemList view={view} selectedId={selected} onSelect={setSelected} header={listHeader} />
        </div>
        <div className={`h-full min-w-0 flex-1 ${selected ? "" : "hidden lg:block"}`}>
          {selected ? (
            <ItemDetail id={selected} onEdit={() => setEditor({ mode: "edit", id: selected })} onBack={() => setSelected(null)} onClosed={() => setSelected(null)} />
          ) : (
            <div className="flex h-full items-center justify-center text-[13px] text-muted">
              <span>
                Select an item, or press <kbd className="rounded-sm border border-line px-1.5">Ctrl</kbd> + <kbd className="rounded-sm border border-line px-1.5">K</kbd> to search.
              </span>
            </div>
          )}
        </div>
      </div>
    );
  } else {
    const pageHeader = (title: string) => (
      <div className="flex h-14 items-center gap-2 border-b border-line px-3">
        <IconButton label="Open navigation" className="lg:hidden" onClick={() => setNavOpen(true)}>
          <Menu aria-hidden />
        </IconButton>
        <h2 className="text-[15px] font-semibold">{title}</h2>
      </div>
    );
    let content;
    switch (view.k) {
      case "security":
        content = <SecurityScreen onOpen={(id) => (setView({ k: "all" }), setSelected(id))} />;
        break;
      case "tools":
        content = <ToolsScreen />;
        break;
      case "settings":
        content = <SettingsScreen />;
        break;
      case "generator":
        content = (
          <div className="mx-auto max-w-[480px] p-6">
            <GeneratorPanel />
          </div>
        );
        break;
      case "admin":
        content = <AdminScreen tab={view.tab} />;
        break;
    }
    const titles: Record<string, string> = { security: "Security", tools: "Import & export", settings: "Settings", generator: "Password generator", admin: "Administration" };
    main = (
      <div className="flex h-full min-w-0 flex-1 flex-col">
        {pageHeader(titles[view.k])}
        <div className="min-h-0 flex-1 overflow-y-auto">{content}</div>
      </div>
    );
  }

  return (
    <div className="flex h-full">
      <aside className={`fixed inset-y-0 left-0 z-30 w-[264px] border-r border-line bg-surface transition-transform duration-200 ease-out lg:static lg:translate-x-0 ${navOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <Sidebar view={view} onNavigate={navigate} />
      </aside>
      {navOpen ? <div className="fixed inset-0 z-20 bg-black/50 lg:hidden" onClick={() => setNavOpen(false)} aria-hidden /> : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-11 items-center gap-2 border-b border-line px-3">
          <button
            className="flex h-8 w-full max-w-[420px] items-center gap-2 rounded-sm border border-line-input px-2.5 text-[13px] text-muted hover:text-fg"
            onClick={() => setPalette(true)}
            data-testid="open-palette"
          >
            <Search className="h-4 w-4" strokeWidth={1.5} aria-hidden />
            <span className="flex-1 text-left">Search vault</span>
            <kbd className="text-[11px]">Ctrl K</kbd>
          </button>
          <div className="flex-1" />
          <span className="hidden text-[12px] text-muted sm:inline">{session?.email}</span>
        </div>
        {warnings.length ? (
          <div className="border-b border-line bg-surface px-4 py-2 text-[12px] text-warning" role="status" data-testid="sync-warnings">
            <span className="inline-flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden />
              {warnings[0]}
              {warnings.length > 1 ? ` (+${warnings.length - 1} more)` : ""}
            </span>
          </div>
        ) : null}
        <div className="min-h-0 flex-1">{main}</div>
      </div>

      <CommandPalette open={palette} onClose={() => setPalette(false)} onPick={(id) => (setView({ k: "all" }), setSelected(id))} />
      {editor ? (
        <ItemEditor
          target={editor}
          onClose={() => setEditor(null)}
          onSaved={(id) => {
            setEditor(null);
            setSelected(id);
          }}
        />
      ) : null}
    </div>
  );
}
