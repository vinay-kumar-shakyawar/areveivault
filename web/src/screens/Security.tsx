import { useEffect, useState, useSyncExternalStore } from "react";
import { ChevronRight } from "lucide-react";
import type { ItemDetail, ItemSummary } from "@arevei/client";
import { Avatar, Button, Status, Toggle } from "@arevei/ui";
import { engine, errorMessage, useApp } from "../lib/app";
import { checkPasswords } from "../lib/hibp";
import { useEngine } from "../lib/hooks";
import { settings } from "../lib/settings";

interface Finding {
  item_id: string;
  detail: string;
}
interface Report {
  weak: Finding[];
  reused: Finding[];
  old: Finding[];
  missing_2fa: Finding[];
  expiring: Finding[];
  total_logins: number;
}

export function SecurityScreen({ onOpen }: { onOpen: (id: string) => void }) {
  const { version } = useApp();
  const now = Math.floor(Date.now() / 1000);
  const { data: report } = useEngine<Report>("security_report", { now: Math.floor(now / 3600) * 3600 });
  const { data: items } = useEngine<ItemSummary[]>("list_items", {});
  const s = useSyncExternalStore(settings.subscribe, settings.get);
  const [breached, setBreached] = useState<Finding[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [hibpError, setHibpError] = useState<string | null>(null);

  useEffect(() => setBreached(null), [version]);

  const titles = new Map((items ?? []).map((i) => [i.id, i]));

  const runHibp = async () => {
    setChecking(true);
    setHibpError(null);
    try {
      const pw = new Map<string, string>();
      for (const it of (items ?? []).filter((i) => i.type === "login" || i.type === "server")) {
        const d = await engine.call<ItemDetail>("get_item", { id: it.id });
        if (d.item.data.password) pw.set(it.id, d.item.data.password);
      }
      const res = await checkPasswords(pw);
      setBreached(
        [...res.entries()].filter(([, n]) => n > 0).map(([id, n]) => ({ item_id: id, detail: `seen ${n.toLocaleString()} times in breaches` })),
      );
    } catch (e) {
      setHibpError(`${errorMessage(e)} — the breach check requires the HIBP connect-src exception in the server's CSP.`);
    } finally {
      setChecking(false);
    }
  };

  const Section = ({ title, tone, findings, empty }: { title: string; tone: "danger" | "warning"; findings: Finding[]; empty: string }) => (
    <section className="av-card overflow-hidden" data-testid={`security-${title.toLowerCase().replace(/\W+/g, "-")}`}>
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <h3 className="text-[14px] font-semibold">{title}</h3>
        {findings.length ? <Status tone={tone}>{findings.length} item{findings.length === 1 ? "" : "s"}</Status> : <Status tone="success">None</Status>}
      </div>
      {findings.length === 0 ? <div className="px-4 py-3 text-[13px] text-muted">{empty}</div> : null}
      {findings.map((f, i) => {
        const it = titles.get(f.item_id);
        return (
          <button key={`${f.item_id}-${i}`} className="row-item last:border-b-0" onClick={() => onOpen(f.item_id)}>
            <Avatar name={it?.title ?? "?"} size={28} />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13px] font-medium">{it?.title ?? "Item"}</span>
              <span className="block truncate text-[12px] text-muted">{f.detail}</span>
            </span>
            <ChevronRight className="h-4 w-4 text-muted" strokeWidth={1.5} aria-hidden />
          </button>
        );
      })}
    </section>
  );

  if (!report) return null;
  const issues = report.weak.length + report.reused.length + report.expiring.length;
  return (
    <div className="mx-auto max-w-[820px] space-y-5 p-5 sm:p-6">
      <div className="av-card p-5">
        <div className="text-[13px] text-muted">Computed on this device. Nothing about your passwords is sent to Arevei.</div>
        <div className="mt-2 text-2xl font-semibold">{issues === 0 ? "Looking good" : `${issues} issue${issues === 1 ? "" : "s"} to review`}</div>
        <div className="mt-1 text-[13px] text-muted">{report.total_logins} passwords analyzed</div>
      </div>
      <Section title="Weak passwords" tone="danger" findings={report.weak} empty="No weak passwords." />
      <Section title="Reused passwords" tone="danger" findings={report.reused} empty="Every password is unique." />
      <Section title="Expiring or expired" tone="warning" findings={report.expiring} empty="Nothing expires in the next 30 days." />
      <Section title="Missing two-factor" tone="warning" findings={report.missing_2fa} empty="All logins on 2FA-capable sites have a one-time code." />
      <Section title="Old passwords" tone="warning" findings={report.old} empty="No passwords older than a year." />

      <section className="av-card p-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-[14px] font-semibold">Breach check (Have I Been Pwned)</h3>
            <p className="mt-1 text-[13px] text-muted">
              Optional. Uses k-anonymity: only the first 5 characters of each password's SHA-1 hash are sent to api.pwnedpasswords.com, with response padding. Off by default.
            </p>
          </div>
          <Toggle checked={s.hibpEnabled} onChange={(v) => settings.update({ hibpEnabled: v })} label="Enable breach check" />
        </div>
        {s.hibpEnabled ? (
          <div className="mt-3 space-y-3">
            <Button onClick={() => void runHibp()} loading={checking}>
              Check passwords now
            </Button>
            {hibpError ? <Status tone="danger">{hibpError}</Status> : null}
            {breached ? <Section title="Breached passwords" tone="danger" findings={breached} empty="None of your passwords appear in known breaches." /> : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}
