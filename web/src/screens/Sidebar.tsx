import { useState } from "react";
import {
  Building2,
  ChevronDown,
  ChevronRight,
  FolderKanban,
  KeySquare,
  Layers,
  Lock,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Star,
  Tag,
  Trash2,
  UploadCloud,
  User,
  UserPlus,
  Users,
  Wand2,
} from "lucide-react";
import type { VaultSummary } from "@arevei/client";
import { Logo } from "@arevei/ui";
import { lock, useApp } from "../lib/app";
import { useEngine } from "../lib/hooks";
import { sameView, type View } from "../lib/nav";

interface VaultList {
  vaults: VaultSummary[];
  clients: { id: string; name: string }[];
  org_admin: boolean;
}

export function Sidebar({ view, onNavigate }: { view: View; onNavigate: (v: View) => void }) {
  const { session } = useApp();
  const { data } = useEngine<VaultList>("list_vaults", {});
  const { data: tags } = useEngine<string[]>("list_tags", {});
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const isAdmin = session?.role === "owner" || session?.role === "admin";

  const Item = ({ to, icon: Icon, children, count, testId }: { to: View; icon: typeof User; children: React.ReactNode; count?: number; testId?: string }) => (
    <button className="nav-item" aria-current={sameView(view, to) ? "page" : undefined} onClick={() => onNavigate(to)} data-testid={testId}>
      <Icon aria-hidden />
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {count ? <span className="text-[11px] tabular-nums text-muted">{count}</span> : null}
    </button>
  );

  const personal = data?.vaults.find((v) => v.kind === "personal");
  const projects = data?.vaults.filter((v) => v.kind === "project") ?? [];
  const byClient = new Map<string, VaultSummary[]>();
  const unassigned: VaultSummary[] = [];
  for (const p of projects) {
    if (p.client_id) byClient.set(p.client_id, [...(byClient.get(p.client_id) ?? []), p]);
    else unassigned.push(p);
  }
  const clients = (data?.clients ?? []).filter((c) => byClient.has(c.id) || isAdmin);

  return (
    <nav className="flex h-full flex-col" aria-label="Vault navigation">
      <div className="flex h-14 items-center px-4">
        <Logo size={24} gradient />
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-4">
        <Item to={{ k: "all" }} icon={Layers} testId="nav-all">
          All items
        </Item>
        {personal ? (
          <Item to={{ k: "vault", id: personal.id }} icon={User} count={personal.item_count} testId="nav-personal">
            Personal Vault
          </Item>
        ) : null}
        <Item to={{ k: "favorites" }} icon={Star}>
          Favorites
        </Item>
        <Item to={{ k: "authenticators" }} icon={ShieldCheck}>
          Authenticators
        </Item>

        {clients.length || unassigned.length ? <div className="section-title">Clients</div> : null}
        {clients.map((c) => {
          const open = !collapsed[c.id];
          const list = byClient.get(c.id) ?? [];
          return (
            <div key={c.id}>
              <div className="flex items-center">
                <button
                  className="av-icon-btn h-7 w-7"
                  aria-label={open ? `Collapse ${c.name}` : `Expand ${c.name}`}
                  aria-expanded={open}
                  onClick={() => setCollapsed({ ...collapsed, [c.id]: open })}
                >
                  {open ? <ChevronDown aria-hidden /> : <ChevronRight aria-hidden />}
                </button>
                <div className="min-w-0 flex-1">
                  <Item to={{ k: "client", id: c.id }} icon={Building2}>
                    {c.name}
                  </Item>
                </div>
              </div>
              {open
                ? list.map((p) => (
                    <div key={p.id} className="pl-7">
                      <Item to={{ k: "vault", id: p.id }} icon={FolderKanban} count={p.item_count} testId={`nav-project-${p.name}`}>
                        {p.name}
                        {!p.unlocked ? <Lock className="ml-1 inline h-3 w-3" aria-label="no key" /> : null}
                      </Item>
                    </div>
                  ))
                : null}
            </div>
          );
        })}
        {unassigned.map((p) => (
          <Item key={p.id} to={{ k: "vault", id: p.id }} icon={FolderKanban} count={p.item_count}>
            {p.name}
          </Item>
        ))}

        {tags && tags.length ? (
          <>
            <div className="section-title">Tags</div>
            {tags.map((t) => (
              <Item key={t} to={{ k: "tag", tag: t }} icon={Tag}>
                {t}
              </Item>
            ))}
          </>
        ) : null}

        <div className="section-title">Tools</div>
        <Item to={{ k: "security" }} icon={ShieldAlert} testId="nav-security">
          Security
        </Item>
        <Item to={{ k: "generator" }} icon={Wand2}>
          Password generator
        </Item>
        <Item to={{ k: "tools" }} icon={UploadCloud} testId="nav-tools">
          Import &amp; export
        </Item>
        <Item to={{ k: "trash" }} icon={Trash2} testId="nav-trash">
          Trash
        </Item>

        {isAdmin ? (
          <>
            <div className="section-title">Admin</div>
            <Item to={{ k: "admin", tab: "members" }} icon={Users} testId="nav-admin-members">
              Members
            </Item>
            <Item to={{ k: "admin", tab: "invites" }} icon={UserPlus} testId="nav-admin-invites">
              Invites
            </Item>
            <Item to={{ k: "admin", tab: "projects" }} icon={KeySquare} testId="nav-admin-projects">
              Clients &amp; projects
            </Item>
            <Item to={{ k: "admin", tab: "audit" }} icon={ScrollText}>
              Audit log
            </Item>
          </>
        ) : null}
      </div>
      <div className="border-t border-line p-2">
        <Item to={{ k: "settings" }} icon={Settings}>
          Settings
        </Item>
        <button className="nav-item" onClick={() => lock()} data-testid="lock-button">
          <Lock aria-hidden />
          Lock now
        </button>
      </div>
    </nav>
  );
}
