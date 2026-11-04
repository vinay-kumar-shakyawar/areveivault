import { useEffect, useState } from "react";
import type { Strength } from "@arevei/client";
import { StrengthMeter } from "@arevei/ui";
import { engine } from "../lib/app";

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

/** Live zxcvbn meter computed by the engine (same estimator on every platform). */
export function useStrength(password: string, inputs: string[] = []): Strength | null {
  const [s, setS] = useState<Strength | null>(null);
  const key = inputs.join("\u0000");
  useEffect(() => {
    let live = true;
    if (!password) {
      setS(null);
      return;
    }
    const t = setTimeout(() => {
      engine
        .call<Strength>("strength", { password, inputs })
        .then((r) => live && setS(r))
        .catch(() => undefined);
    }, 120);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [password, key]);
  return s;
}

export function StrengthView({ strength }: { strength: Strength | null }) {
  const score = strength?.score ?? 0;
  return (
    <div className="space-y-1.5" data-testid="strength" data-score={strength ? score : ""}>
      <StrengthMeter score={strength ? Math.max(score, 1) : 0} />
      {strength ? (
        <div className="text-[12px] text-muted">
          <span className="font-medium text-fg">{LABELS[score]}</span>
          {" · "}cracking time {strength.crack_time}
          {strength.warning ? <div className="mt-0.5">{strength.warning}</div> : null}
          {score < 3 && strength.suggestions[0] ? <div className="mt-0.5">{strength.suggestions[0]}</div> : null}
        </div>
      ) : null}
    </div>
  );
}
