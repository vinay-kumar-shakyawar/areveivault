import { useCallback, useEffect, useState } from "react";
import { Copy, RefreshCw } from "lucide-react";
import { Button, Field, IconButton, SecretText, Select, Toggle, type CharRun } from "@arevei/ui";
import { copyText, engine } from "../lib/app";

interface Opts {
  mode: "password" | "passphrase";
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

const DEFAULTS: Opts = {
  mode: "password",
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoid_ambiguous: true,
  words: 5,
  separator: "-",
  capitalize: true,
  include_number: true,
};

/** Password / passphrase generator (engine CSPRNG). `onUse` makes it usable inline in forms. */
export function GeneratorPanel({ onUse }: { onUse?: (value: string) => void }) {
  const [o, setO] = useState<Opts>(DEFAULTS);
  const [value, setValue] = useState("");
  const [runs, setRuns] = useState<CharRun[]>([]);
  const [entropy, setEntropy] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const gen = useCallback(async () => {
    try {
      const r =
        o.mode === "password"
          ? await engine.call<{ value: string; entropy_bits: number }>("generate_password", {
              options: { length: o.length, lowercase: o.lowercase, uppercase: o.uppercase, digits: o.digits, symbols: o.symbols, avoid_ambiguous: o.avoid_ambiguous },
            })
          : await engine.call<{ value: string; entropy_bits: number }>("generate_passphrase", {
              options: { words: o.words, separator: o.separator, capitalize: o.capitalize, include_number: o.include_number },
            });
      setValue(r.value);
      setEntropy(r.entropy_bits);
      setRuns(await engine.call<CharRun[]>("tokenize", { password: r.value }));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not generate");
    }
  }, [o]);

  useEffect(() => {
    void gen();
  }, [gen]);

  const row = (label: string, key: keyof Opts) => (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="text-[13px]">{label}</span>
      <Toggle checked={o[key] as boolean} onChange={(v) => setO({ ...o, [key]: v })} label={label} />
    </div>
  );

  return (
    <div className="space-y-4" data-testid="generator">
      <div className="flex items-center gap-2 rounded border border-line bg-bg px-3 py-3">
        <div className="min-w-0 flex-1 text-[15px]" data-testid="generated-value" data-value={value}>
          <SecretText runs={runs} />
        </div>
        <IconButton label="Regenerate" onClick={() => void gen()}>
          <RefreshCw aria-hidden />
        </IconButton>
        <IconButton label="Copy generated password" onClick={() => void copyText(value, "Generated password")}>
          <Copy aria-hidden />
        </IconButton>
      </div>
      <div className="text-[12px] text-muted">≈ {Math.round(entropy)} bits of entropy</div>
      {error ? <div className="text-[13px] text-danger">{error}</div> : null}

      <div className="grid grid-cols-2 gap-1 rounded-sm border border-line p-1" role="tablist">
        {(["password", "passphrase"] as const).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={o.mode === m}
            className={`rounded-sm py-1.5 text-[13px] capitalize ${o.mode === m ? "bg-raised text-fg" : "text-muted"}`}
            onClick={() => setO({ ...o, mode: m })}
          >
            {m}
          </button>
        ))}
      </div>

      {o.mode === "password" ? (
        <div>
          <Field label={`Length: ${o.length}`} htmlFor="gen-len">
            <input id="gen-len" type="range" min={8} max={64} value={o.length} onChange={(e) => setO({ ...o, length: Number(e.target.value) })} className="w-full accent-[var(--silver-strong)]" />
          </Field>
          {row("Lowercase (a–z)", "lowercase")}
          {row("Uppercase (A–Z)", "uppercase")}
          {row("Digits (0–9)", "digits")}
          {row("Symbols (!@#…)", "symbols")}
          {row("Avoid ambiguous characters", "avoid_ambiguous")}
        </div>
      ) : (
        <div className="space-y-2">
          <Field label={`Words: ${o.words}`} htmlFor="gen-words">
            <input id="gen-words" type="range" min={3} max={10} value={o.words} onChange={(e) => setO({ ...o, words: Number(e.target.value) })} className="w-full accent-[var(--silver-strong)]" />
          </Field>
          <Field label="Separator" htmlFor="gen-sep">
            <Select id="gen-sep" value={o.separator} onChange={(e) => setO({ ...o, separator: e.target.value })}>
              <option value="-">Hyphen (-)</option>
              <option value=".">Period (.)</option>
              <option value="_">Underscore (_)</option>
              <option value=" ">Space</option>
            </Select>
          </Field>
          {row("Capitalize words", "capitalize")}
          {row("Include a number", "include_number")}
        </div>
      )}

      {onUse ? (
        <Button variant="primary" block onClick={() => onUse(value)} data-testid="generator-use">
          Use this password
        </Button>
      ) : null}
    </div>
  );
}
