import { describe, expect, it } from "vitest";
import { SyncManager, type Api, type Engine } from "@arevei/client";

function harness(responses: ((since: number) => any)[]) {
  const calls: number[] = [];
  let i = 0;
  const api = { sync: async (since: number) => (calls.push(since), responses[Math.min(i++, responses.length - 1)](since)) } as unknown as Api;
  const engine = { call: async () => ({ warnings: [] }) } as unknown as Engine;
  const pins = { get: async () => null, set: async () => undefined };
  return { sm: new SyncManager(engine, api, pins), calls };
}

const payload = (revision: number, vaults: string[]) => ({ revision, vaults: vaults.map((id) => ({ id })), items: [], org: null });

describe("SyncManager", () => {
  it("re-pulls everything when a new vault is granted (its items predate our cursor)", async () => {
    const { sm, calls } = harness([() => payload(10, ["personal"]), () => payload(12, ["personal", "project"]), () => payload(12, ["personal", "project"])]);
    await sm.sync(true);
    await sm.sync();
    expect(calls).toEqual([0, 10, 0]);
  });

  it("stays incremental when the vault set is unchanged or shrinks", async () => {
    const { sm, calls } = harness([() => payload(10, ["a", "b"]), () => payload(11, ["a", "b"]), () => payload(12, ["a"])]);
    await sm.sync(true);
    await sm.sync();
    await sm.sync();
    expect(calls).toEqual([0, 10, 11]);
  });
});
