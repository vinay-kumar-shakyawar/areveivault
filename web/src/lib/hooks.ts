import { useEffect, useRef, useState } from "react";
import { engine, useApp } from "./app";

/** Runs an engine query and re-runs it whenever vault data changes (state.version) or deps change. */
export function useEngine<T>(method: string, args: Record<string, unknown>, deps: unknown[] = []): { data: T | undefined; error: string | null; loading: boolean } {
  const { version, phase } = useApp();
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const key = JSON.stringify(args);
  useEffect(() => {
    if (phase !== "unlocked") return;
    let live = true;
    setLoading(true);
    engine
      .call<T>(method, args)
      .then((d) => {
        if (live) {
          setData(d);
          setError(null);
        }
      })
      .catch((e: Error) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, key, version, phase, ...deps]);
  return { data, error, loading };
}

/** Ticks every second (TOTP countdowns, clipboard timers). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function useLatest<T>(v: T) {
  const r = useRef(v);
  r.current = v;
  return r;
}
