import { describe, expect, it } from "vitest";
import { randomToken, validateContentMessage, validateExternalMessage, validateMenuMessage, validatePromptMessage } from "../src/shared/messages";

const tok = randomToken();

describe("content messages", () => {
  it("accepts well-formed messages", () => {
    expect(validateContentMessage({ type: "cs:hello" })).not.toBeNull();
    expect(validateContentMessage({ type: "cs:open-menu", field: "password", formKind: "login" })).not.toBeNull();
    expect(validateContentMessage({ type: "cs:capture", username: "me", password: "pw", formKind: "signup" })).not.toBeNull();
  });
  it("rejects content scripts trying to claim a URL/origin/frame", () => {
    expect(validateContentMessage({ type: "cs:open-menu", field: "password", formKind: "login", url: "https://bank.com" })).toBeNull();
    expect(validateContentMessage({ type: "cs:hello", frameId: 0 })).toBeNull();
  });
  it("rejects bad types, sizes and unknown messages", () => {
    expect(validateContentMessage({ type: "cs:open-menu", field: "credit-card", formKind: "login" })).toBeNull();
    expect(validateContentMessage({ type: "cs:capture", username: "x".repeat(600), password: "p", formKind: "login" })).toBeNull();
    expect(validateContentMessage({ type: "cs:capture", username: "x", password: "", formKind: "login" })).toBeNull();
    expect(validateContentMessage({ type: "cs:capture", username: "x", password: "p".repeat(2000), formKind: "login" })).toBeNull();
    expect(validateContentMessage({ type: "fill", username: "x" })).toBeNull();
    expect(validateContentMessage(null)).toBeNull();
    expect(validateContentMessage("cs:hello")).toBeNull();
  });
});

describe("menu / prompt port messages", () => {
  it("validates tokens and item ids", () => {
    expect(validateMenuMessage({ type: "menu:init", token: tok })).not.toBeNull();
    expect(validateMenuMessage({ type: "menu:init", token: "short" })).toBeNull();
    expect(validateMenuMessage({ type: "menu:select", token: tok, itemId: "4f1c-aa", confirmInsecure: false, visible: true })).not.toBeNull();
    expect(validateMenuMessage({ type: "menu:select", token: tok, itemId: "../x", confirmInsecure: false, visible: true })).toBeNull();
    expect(validatePromptMessage({ type: "prompt:save", token: tok, vaultId: "v-1", title: "Acme", visible: true })).not.toBeNull();
    expect(validatePromptMessage({ type: "prompt:save", token: tok, vaultId: "v-1", title: "Acme" })).toBeNull();
  });
});

describe("external (vault web app) messages", () => {
  it("only lock-state messages are accepted, never keys", () => {
    for (const t of ["locked", "unlocked", "lock-now", "verify-build"]) expect(validateExternalMessage({ type: t })).not.toBeNull();
    expect(validateExternalMessage({ type: "unlocked", key: "AAAA" })).toBeNull();
    expect(validateExternalMessage({ type: "export-session" })).toBeNull();
  });
});

it("randomToken is url-safe and unique", () => {
  const a = randomToken();
  expect(a).toMatch(/^[A-Za-z0-9_-]{32}$/);
  expect(a).not.toBe(randomToken());
});
