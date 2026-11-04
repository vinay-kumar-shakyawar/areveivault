import { beforeEach, describe, expect, it } from "vitest";
import { capturedPassword, classifyInput, fillOtp, findGroups, formKind, isFillable } from "../src/shared/fields";

// jsdom has no layout: give every element a visible box unless it opts out.
beforeEach(() => {
  HTMLElement.prototype.getBoundingClientRect = function () {
    const hidden = (this as HTMLElement).dataset.zero === "1";
    const w = hidden ? 0 : 200;
    const h = hidden ? 0 : 30;
    return { x: 0, y: 0, top: 0, left: 0, right: w, bottom: h, width: w, height: h, toJSON() {} } as DOMRect;
  };
});

const input = (html: string) => {
  document.body.innerHTML = html;
  return document.querySelector("input") as HTMLInputElement;
};

describe("classifyInput", () => {
  it("uses autocomplete attributes first", () => {
    expect(classifyInput(input('<input type="password" autocomplete="new-password">'))).toBe("new-password");
    expect(classifyInput(input('<input type="password" autocomplete="current-password">'))).toBe("current-password");
    expect(classifyInput(input('<input type="text" autocomplete="one-time-code">'))).toBe("otp");
    expect(classifyInput(input('<input type="text" autocomplete="username">'))).toBe("username");
  });
  it("falls back to name/id heuristics", () => {
    expect(classifyInput(input('<input type="password" name="confirm_password">'))).toBe("new-password");
    expect(classifyInput(input('<input type="password" id="old-pass">'))).toBe("current-password");
    expect(classifyInput(input('<input type="password" name="pw">'))).toBe("password");
    expect(classifyInput(input('<input type="email" name="x">'))).toBe("username");
    expect(classifyInput(input('<input name="login_id">'))).toBe("username");
    expect(classifyInput(input('<input name="otp_code" maxlength="6" inputmode="numeric">'))).toBe("otp");
  });
  it("ignores irrelevant fields", () => {
    expect(classifyInput(input('<input name="q" type="search">'))).toBeNull();
    expect(classifyInput(input('<input name="search_user">'))).toBeNull();
    expect(classifyInput(input('<input type="checkbox" name="remember">'))).toBeNull();
    expect(classifyInput(input('<input name="first_name">'))).toBeNull();
  });
});

describe("isFillable", () => {
  it("rejects hidden, transparent, disabled and zero-size fields", () => {
    document.body.innerHTML = `
      <input id="ok" type="password">
      <input id="none" type="password" style="display:none">
      <div style="opacity:0"><input id="transparent" type="password"></div>
      <input id="disabled" type="password" disabled>
      <input id="ro" type="password" readonly>
      <input id="zero" type="password" data-zero="1">
      <input id="hiddentype" type="hidden">`;
    const get = (id: string) => document.getElementById(id) as HTMLInputElement;
    expect(isFillable(get("ok"))).toBe(true);
    for (const id of ["none", "transparent", "disabled", "ro", "zero", "hiddentype"]) expect(isFillable(get(id)), id).toBe(false);
  });
});

describe("findGroups", () => {
  it("detects a login form and its username", () => {
    document.body.innerHTML = `<form><input name="q" placeholder="search"><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`;
    const [g] = findGroups(document);
    expect(g.kind).toBe("login");
    expect(g.username?.name).toBe("email");
    expect(g.passwords).toHaveLength(1);
  });
  it("detects signup and change-password forms", () => {
    document.body.innerHTML = `<form><input name="user"><input type="password" name="pw"><input type="password" name="confirm"></form>`;
    expect(findGroups(document)[0].kind).toBe("signup");
    document.body.innerHTML = `<form><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form>`;
    expect(findGroups(document)[0].kind).toBe("change");
  });
  it("handles formless SPA pages and skips hidden traps", () => {
    document.body.innerHTML = `<div><input id="u" type="text" name="username"><input id="p" type="password"><input id="trap" type="password" style="display:none"></div>`;
    const [g] = findGroups(document);
    expect(g.root).toBe(document);
    expect(g.passwords.map((p) => p.el.id)).toEqual(["p"]);
  });
  it("detects OTP-only forms", () => {
    document.body.innerHTML = `<form><input autocomplete="one-time-code"></form>`;
    expect(findGroups(document)[0].kind).toBe("otp");
  });
});

describe("capturedPassword / formKind", () => {
  it("takes the new password on change forms", () => {
    document.body.innerHTML = `<form><input type="password" autocomplete="current-password" value="old"><input type="password" autocomplete="new-password" value="new1"><input type="password" autocomplete="new-password" value="new1"></form>`;
    const [g] = findGroups(document);
    expect(capturedPassword(g)).toBe("new1");
  });
  it("formKind basics", () => {
    expect(formKind([{ kind: "password" }], [])).toBe("login");
    expect(formKind([], [document.createElement("input")])).toBe("otp");
  });
});

describe("fillOtp", () => {
  it("splits across single-digit inputs", () => {
    document.body.innerHTML = Array.from({ length: 6 }, () => '<input maxlength="1">').join("");
    const fields = Array.from(document.querySelectorAll("input"));
    fillOtp(fields, "123456");
    expect(fields.map((f) => f.value).join("")).toBe("123456");
  });
});
