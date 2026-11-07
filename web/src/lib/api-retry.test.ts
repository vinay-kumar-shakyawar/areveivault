import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Api, ApiError } from "@arevei/client";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("Api gateway retry", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("retries 502s until the backend answers and reports waking once", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("Bad Gateway", { status: 502 }))
      .mockResolvedValueOnce(new Response("Bad Gateway", { status: 502 }))
      .mockResolvedValueOnce(json(200, { salt: "s", kdf: {} }));
    vi.stubGlobal("fetch", fetchMock);
    const onWaking = vi.fn();
    const api = new Api({ baseUrl: "", onWaking });

    const p = api.prelogin("a@b.c");
    await vi.runAllTimersAsync();
    await expect(p).resolves.toEqual({ salt: "s", kdf: {} });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(onWaking).toHaveBeenCalledTimes(1);
  });

  it("gives up after the retry budget and surfaces the gateway error", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("Bad Gateway", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new Api({ baseUrl: "" });

    const p = api.prelogin("a@b.c");
    p.catch(() => {});
    await vi.runAllTimersAsync();
    await expect(p).rejects.toMatchObject({ status: 502 } satisfies Partial<ApiError>);
    expect(fetchMock).toHaveBeenCalledTimes(11);
  });

  it("does not retry ordinary API errors", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(400, { error: "bad_request", message: "missing email" }));
    vi.stubGlobal("fetch", fetchMock);
    const onWaking = vi.fn();
    const api = new Api({ baseUrl: "", onWaking });

    await expect(api.prelogin("a@b.c")).rejects.toMatchObject({ status: 400, message: "missing email" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(onWaking).not.toHaveBeenCalled();
  });
});
