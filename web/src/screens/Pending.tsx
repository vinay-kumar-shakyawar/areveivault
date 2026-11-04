import { useEffect, useState } from "react";
import { Hourglass, RefreshCw } from "lucide-react";
import { Button } from "@arevei/ui";
import { AuthLayout } from "../components/AuthLayout";
import { engine, errorMessage, lock, logout, refresh } from "../lib/app";
import { toast } from "../lib/toast";

/** Invited members wait here until an admin verifies their fingerprint and approves. */
export function PendingScreen({ onContinue }: { onContinue: () => void }) {
  const [fp, setFp] = useState<string>("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void engine.call<{ fingerprint: string }>("my_fingerprint").then((r) => setFp(r.fingerprint));
  }, []);

  const check = async () => {
    setBusy(true);
    try {
      await refresh(true);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      footer={
        <span className="flex justify-center gap-4">
          <button className="underline underline-offset-2" onClick={() => lock()}>
            Lock
          </button>
          <button className="underline underline-offset-2" onClick={() => void logout()}>
            Sign out
          </button>
        </span>
      }
    >
      <div className="space-y-4">
        <h1 className="flex items-center gap-2 text-lg font-semibold">
          <Hourglass className="h-5 w-5 text-silver-strong" strokeWidth={1.5} aria-hidden /> Waiting for approval
        </h1>
        <p className="text-[13px] text-muted">
          An administrator must verify your identity before sharing client projects with you. Read this fingerprint to them over a call or in person. They'll compare it with what they see.
        </p>
        <div className="rounded border border-line bg-bg p-4 text-center font-mono text-[15px] tracking-wider" data-testid="my-fingerprint">
          {fp || "…"}
        </div>
        <div className="flex gap-2">
          <Button onClick={() => void check()} loading={busy}>
            <RefreshCw aria-hidden /> Check again
          </Button>
          <Button variant="primary" className="flex-1" onClick={onContinue}>
            Open my Personal Vault
          </Button>
        </div>
      </div>
    </AuthLayout>
  );
}
