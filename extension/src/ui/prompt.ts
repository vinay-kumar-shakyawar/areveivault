/** Save / update prompt (extension-origin iframe). Never receives the password itself. */

import { el } from "./dom";
import { isFrameVisible, watchVisibility } from "./visibility";

const token = location.hash.slice(1);
const port = chrome.runtime.connect({ name: "prompt" });
const app = document.getElementById("app")!;
watchVisibility(document.body);

function head(text: string) {
  return el("div", { class: "menu-head" }, [
    el("span", { class: "logo-dot" }),
    el("span", { class: "brand" }, [text]),
    el("button", { class: "icon-btn", "aria-label": "Dismiss", onclick: () => port.postMessage({ type: "prompt:dismiss", token }) }, ["✕"]),
  ]);
}

port.onMessage.addListener((m) => {
  if (m.type === "state") render(m);
  else if (m.type === "done") app.replaceChildren(head("Arevei Vault"), el("p", { class: "pad", role: "status" }, [m.kind === "saved" ? "Saved." : "Updated."]));
  else if (m.type === "error") {
    app.querySelector(".banner")?.remove();
    app.append(el("div", { class: "banner danger", role: "alert" }, [m.message]));
  }
});

function render(s: any) {
  if (s.state === "locked") {
    app.replaceChildren(head("Save login?"), el("p", { class: "pad" }, [`Unlock Arevei Vault from the toolbar to save your login for ${s.host}.`]));
    return;
  }
  if (s.kind === "update") {
    app.replaceChildren(
      head("Update password?"),
      el("p", { class: "pad" }, [`Update the saved password for `, el("strong", {}, [s.itemTitle ?? s.host]), s.username ? ` (${s.username})` : "", "?"]),
      el("div", { class: "actions" }, [
        el("button", { class: "secondary", onclick: () => port.postMessage({ type: "prompt:dismiss", token }) }, ["Not now"]),
        el("button", { class: "primary", "data-action": "update", onclick: () => port.postMessage({ type: "prompt:update", token, visible: isFrameVisible() }) }, ["Update"]),
      ]),
    );
    return;
  }
  const title = el("input", { class: "input", value: s.host, "aria-label": "Title" }) as HTMLInputElement;
  const select = el("select", { class: "input", "aria-label": "Save to" }) as HTMLSelectElement;
  for (const v of s.vaults) {
    select.append(el("option", { value: v.id }, [v.kind === "personal" ? "Personal Vault" : `${v.client_name ? v.client_name + " → " : ""}${v.name}`]));
  }
  app.replaceChildren(
    head("Save login?"),
    el("div", { class: "pad form" }, [
      el("p", { class: "muted" }, [`${s.username || "(no username)"} on ${s.host}`]),
      el("label", {}, ["Title", title]),
      el("label", {}, ["Save to", select]),
    ]),
    el("div", { class: "actions" }, [
      el("button", { class: "link", onclick: () => port.postMessage({ type: "prompt:never", token }) }, ["Never for this site"]),
      el("button", { class: "secondary", onclick: () => port.postMessage({ type: "prompt:dismiss", token }) }, ["Not now"]),
      el(
        "button",
        {
          class: "primary",
          "data-action": "save",
          onclick: () => port.postMessage({ type: "prompt:save", token, vaultId: select.value, title: title.value, visible: isFrameVisible() }),
        },
        ["Save"],
      ),
    ]),
  );
}

app.replaceChildren(head("Arevei Vault"), el("p", { class: "pad muted" }, ["Loading…"]));
port.postMessage({ type: "prompt:init", token });
