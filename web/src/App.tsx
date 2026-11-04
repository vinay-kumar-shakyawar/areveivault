import { useEffect, useState } from "react";
import { Spinner } from "@arevei/ui";
import { useApp } from "./lib/app";
import { Toaster } from "./components/Toaster";
import { AuthScreen } from "./screens/Auth";
import { UnlockScreen } from "./screens/Unlock";
import { PendingScreen } from "./screens/Pending";
import { VaultShell } from "./screens/VaultShell";

export function App() {
  const { phase, session } = useApp();
  const [personalOnly, setPersonalOnly] = useState(false);

  useEffect(() => {
    document.title = phase === "unlocked" ? "Arevei Vault" : phase === "locked" ? "Locked · Arevei Vault" : "Arevei Vault";
  }, [phase]);

  let body;
  if (phase === "boot") {
    body = (
      <div className="flex h-full items-center justify-center">
        <Spinner />
      </div>
    );
  } else if (phase === "signed_out") {
    body = <AuthScreen />;
  } else if (phase === "locked") {
    body = <UnlockScreen />;
  } else if (session?.status === "pending_approval" && !personalOnly) {
    body = <PendingScreen onContinue={() => setPersonalOnly(true)} />;
  } else {
    body = <VaultShell />;
  }

  return (
    <>
      {body}
      <Toaster />
    </>
  );
}
