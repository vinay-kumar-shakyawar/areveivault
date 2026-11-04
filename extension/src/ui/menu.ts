/** Inline autofill menu (extension-origin iframe). Shows titles/usernames of matching items only. */

import { isFrameVisible, watchVisibility } from "./visibility";
import { el, initials } from "./dom";

const token = location.hash.slice(1);
const port = chrome.runtime.connect({ name: "menu" });
const app = document.getElementById("app")!;
watchVisibility(document.body);

interface MenuItem {
  id: string;
  title: string;
  subtitle: string;
  insecure: boolean;
  hasTotp: boolean;
}

let state: any = null;
let confirming: string | null = null;

function render() {
  app.replaceChildren();
  const header = el("div", { class: "menu-head" }, [
    el("span", { class: "logo-dot" }),
    el("span", { class: "brand" }, ["Arevei Vault"]),
    el("button", { class: "icon-btn", "aria-label": "Close", onclick: () => port.postMessage({ type: "menu:close", token }) }, ["✕"]),
  ]);
  app.append(header);
  if (!state) {
    app.append(el("p", { class: "muted pad" }, ["Loading…"]));
    return;
  }
  if (state.state === "locked") {
    app.append(el("p", { class: "pad" }, ["Vault is locked. Unlock it from the Arevei Vault toolbar button."]));
    return;
  }
  if (state.lookalike) {
    app.append(
      el("div", { class: "banner danger", role: "alert" }, [
        el("strong", {}, ["Possible phishing site. "]),
        `${state.lookalike.page_domain} ${state.lookalike.reason} (${state.lookalike.imitates}). Autofill is disabled here.`,
      ]),
    );
    return;
  }
  if (state.crossOrigin && !state.items.length) {
    app.append(el("div", { class: "banner warning", role: "status" }, ["This login form is embedded from another site. Autofill is blocked."]));
  }
  if (state.insecurePage) {
    app.append(el("div", { class: "banner warning", role: "status" }, ["This page is not secure (HTTP). Filling requires confirmation."]));
  }
  const list = el("ul", { class: "list", role: "listbox", "aria-label": `Logins for ${state.host}` });
  for (const it of state.items as MenuItem[]) {
    const needsConfirm = confirming === it.id;
    list.append(
      el("li", {}, [
        el(
          "button",
          {
            class: "item",
            role: "option",
            "data-item-id": it.id,
            onclick: () => select(it.id, needsConfirm),
          },
          [
            el("span", { class: "avatar" }, [initials(it.title)]),
            el("span", { class: "text" }, [
              el("span", { class: "title" }, [it.title]),
              el("span", { class: "sub" }, [needsConfirm ? "Click again to fill on this insecure page" : it.subtitle || "—"]),
            ]),
          ],
        ),
      ]),
    );
  }
  if (!state.items.length) list.append(el("li", { class: "muted pad empty" }, [`No saved logins for ${state.host}`]));
  app.append(list);
  if (state.canGenerate) {
    app.append(el("button", { class: "generate", onclick: () => port.postMessage({ type: "menu:generate", token, visible: isFrameVisible() }) }, ["Suggest strong password"]));
  }
}

function select(itemId: string, confirmInsecure: boolean) {
  port.postMessage({ type: "menu:select", token, itemId, confirmInsecure, visible: isFrameVisible() });
}

port.onMessage.addListener((m) => {
  if (m.type === "state") {
    state = m;
    render();
  } else if (m.type === "refused") {
    if (m.reason === "needs-confirm") {
      confirming = m.itemId;
      render();
    } else {
      showError(
        m.reason === "obscured"
          ? "The menu is covered by something on the page. Autofill was blocked."
          : m.reason === "lookalike"
            ? "Look-alike domain: autofill blocked."
            : "This login doesn't match this site.",
      );
    }
  } else if (m.type === "error") {
    showError(m.message);
  } else if (m.type === "done") {
    app.replaceChildren(el("p", { class: "pad" }, ["Filled."]));
  }
});

function showError(msg: string) {
  app.querySelector(".banner.error")?.remove();
  app.insertBefore(el("div", { class: "banner danger error", role: "alert" }, [msg]), app.children[1] ?? null);
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") port.postMessage({ type: "menu:close", token });
});

render();
port.postMessage({ type: "menu:init", token });
