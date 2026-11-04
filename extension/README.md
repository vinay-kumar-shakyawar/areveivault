# Arevei Vault — browser extension (Manifest V3)

Saves and autofills credentials and one-time codes, and replaces Chrome's built-in password manager. All cryptography runs in the Rust engine (`/core`, compiled to WASM) inside the service worker. Design references: [architecture §13](../docs/architecture.md) and threat model T3/T4.

## Build

```bash
pnpm build:wasm                      # once, from the repo root (needs Rust + wasm-bindgen)
pnpm --filter extension build        # release → extension/dist/chrome, extension/dist/firefox
VAULT_ORIGIN=https://vault.arevei.com BUNDLE_MANIFEST_URL=https://…/bundle-hashes.json pnpm --filter extension build
node extension/build.mjs --dev       # also allows http://localhost:5173 as the vault web app
```

Load `dist/chrome` with chrome://extensions → Developer mode → Load unpacked.

## Test

```bash
pnpm --filter extension typecheck
pnpm --filter extension test         # Vitest (jsdom): field heuristics, frame policy, message validation, pending-capture TTL
pnpm --filter extension e2e          # Playwright: builds the E2E variant and runs /e2e/extension against local fixture sites
```

The E2E build (`build.mjs --e2e`) adds a service-worker hook (`self.__e2eSeed`) that creates a local vault without a server. It's gated on the `__E2E__` build constant, so release bundles don't contain it (verified: `grep __e2e dist/chrome/sw.js` finds nothing in a release build). **Never ship an E2E build.**

E2E runs Chromium with `--headless=new`, because Playwright 1.48's headless shell can't load extensions. Test hosts are mapped to 127.0.0.1 with `--host-resolver-rules`, and HTTPS uses a throwaway self-signed certificate in `e2e/extension/fixtures/certs`.

## Permissions

| Permission | Why it's needed |
|---|---|
| `host_permissions: <all_urls>` + content script (all frames) | Detect login forms and draw the inline icon on any site. This is the one broad permission, and inline autofill can't work without it. Content scripts never receive vault data except the single credential the user picked for their own frame. |
| `storage` | `local`: ciphertext sync cache, encrypted keyset, session token, settings, the "never save" list (stored as domain hashes). `session`: the unlocked engine session plus in-flight menu contexts and save prompts. It's memory-only, limited to trusted contexts, and cleared when the browser closes. |
| `scripting` | Inject the content script into tabs already open when the extension is installed or updated |
| `contextMenus` | Fill login, Generate password, Copy one-time code |
| `offscreen` | Write the clipboard from MV3, and clear it after 30 s |
| `alarms` | Auto-lock timer (default 5 min) and 60 s background sync, both of which survive service-worker suspension |
| `idle` | Lock when the OS screen locks |
| `activeTab` | The popup reads the current tab URL to show matching items |
| `privacy` (**optional**) | Requested only in onboarding, with consent, to set `passwordSavingEnabled = false` (reversible) |
| `commands` (manifest key) | `Ctrl/Cmd+Shift+L` fills the best match, or opens the menu if there are several |
| Not requested | `tabs`, `webRequest`, `webNavigation`, `cookies`, `history`, `clipboardRead` |

`web_accessible_resources` exposes only `menu.html` and `prompt.html`, with `use_dynamic_url`. `externally_connectable` allows only the vault origin, and that channel accepts only `locked` / `unlocked` / `lock-now` / `verify-build`. **Key material never crosses it.** The extension-page CSP is `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`.

## Security design

- **Origin trust.** The service worker takes page URL, origin, and frame only from `chrome.runtime.MessageSender` (`url`, `origin`, `frameId`, `tab.url`). Content-script messages are schema-validated and must not carry a URL (`src/shared/messages.ts`). `about:blank` frames are accepted only when they're same-origin with the top page.
- **No fill without a gesture.** Fills happen only on a trusted click on the inline icon, then a click in the menu, or on the keyboard command or context menu. Nothing fills on page load.
- **Re-validation at fill time.** The engine's `match_url` is run again (with `top_url` for cross-origin-frame checks), followed by `fill_data`, which re-checks the match, look-alike domains, and HTTPS downgrade. Look-alikes are refused. Cross-origin iframes get no matches unless the item allow-lists that frame. HTTP needs an explicit second click.
- **Inline UI isolation.** The menu and prompts are extension-origin iframes inside a closed Shadow DOM host, so the page can't read titles or usernames. Clickjacking defenses: the content script checks that the host is topmost and fully opaque (polled while open), and the iframe checks IntersectionObserver v2 `isVisible`. Clicks are refused while the UI is obscured.
- **Only visible fields are filled.** Fields hidden by `display:none`, `visibility`, opacity below 0.1 (on the field or any ancestor), zero size, an off-screen position, `disabled`, or `readonly` are never filled.
- **Save and update.** Captured credentials go straight to the service worker and are held per tab for 5 minutes (mirrored to `storage.session` so a service-worker restart doesn't lose them). The prompt never receives the password. New logins save only the site **origin** as the URL, never the path or query, which can contain tokens.
- **Session token.** The extension authenticates with a Bearer `session_token`, because an MV3 service worker can't rely on SameSite=Strict cookies. It's stored in `chrome.storage.local`. It's not a key and can't decrypt anything, and it's revocable from Settings → Devices and invalidated on sign-out. **Tradeoff:** anyone who copies the browser profile gets a usable session until it expires or is revoked. They still need the master password and Secret Key to decrypt.
- **The Secret Key on this device** is encrypted with a non-extractable AES-GCM WebCrypto key in the extension's IndexedDB.
- **Auto-lock** happens after inactivity (alarm), on OS screen lock (`idle`), on browser close (because the session lives in memory-only `storage.session`), and when the vault web app signals `locked`.
- **Clipboard.** It's always cleared 30 s after a copy. We can't check whether the clipboard still holds our value without `clipboardRead`. OS clipboard history (Win+V) may keep a copy.
- **Build verifier (`verify-build`).** It hashes the served `index.html` and its scripts and stylesheets, and compares them with `BUNDLE_MANIFEST_URL`. If that isn't configured, it reports `unverified`.

## Replacing Chrome's password manager

Onboarding (it opens on install):
1. Export from `chrome://password-manager/settings`.
2. Import the CSV. It's parsed and encrypted locally, and only ciphertext is uploaded.
3. Delete the CSV.
4. Optionally turn off Chrome's password saving through the `privacy` permission. This is reversible from the same page.

**On Arevei-managed machines, use policy instead.** It's more robust and also handles private distribution:

| Policy | Value |
|---|---|
| `PasswordManagerEnabled` | `false` (turns off Chrome's saving and filling) |
| `ExtensionInstallForcelist` | `<extension-id>;https://clients2.google.com/service/update2/crx`, or a self-hosted update URL for unlisted builds |
| `ExtensionSettings` | Optionally block all other extensions except an allowlist (threat model T4) |

Set these through Google Admin (Chrome Browser Cloud Management), Windows GPO (`HKLM\Software\Policies\Google\Chrome`), or macOS MDM profiles. Edge uses the same policy names under `Microsoft\Edge`.

## Firefox

`dist/firefox` uses `background.scripts` and a `gecko` id, and drops `offscreen` and `externally_connectable`, neither of which Firefox supports. The popup writes the clipboard itself there, and it can only auto-clear while the popup stays open. The Firefox build has not been tested in Firefox yet.

## Known gaps

- Verified only against the local E2E vault. Sign-in, MFA, sync, and audit upload against the real server haven't been exercised yet, because the server was being built in parallel.
- Passkey (WebAuthn PRF) unlock isn't implemented. Unlock uses the master password.
- Autofill coverage on the top-50 Arevei sites needs the site list and a live test pass.
