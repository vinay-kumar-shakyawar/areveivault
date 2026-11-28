# Landing page

The static marketing page for Arevei Vault, positioned for solo founders. The copy comes from the "Arevei Vault — Landing Page Copy (Solo Founders)" doc.

- The page itself uses no JavaScript. By default it ships under `default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:`, plus `form-action` for the one form below.
- Google Tag Manager is opt-in: build with `GTM_ID=GTM-XXXXXXX` and every page loads `gtm-init.js` and the container, and the CSP also admits `www.googletagmanager.com` scripts and Google Analytics requests (no inline script). It is set in `deploy/vercel/build-web.sh` for the `/welcome` copy on `vault.arevei.com` and in `landing/vercel.json` for the standalone project. On `/welcome` the tag runs on the vault's origin, so treat edit access to the GTM container like deploy access: the CSP allows only Google hosts and no inline script, so do not add Custom HTML tags.
- Colors come from `packages/ui/src/tokens.css`, the same tokens as the app. Dark by default, and it follows the system light/dark setting.
- Fonts are self-hosted from the web app's `@fontsource` packages, so run `pnpm install` first.

```bash
node landing/build.mjs            # → landing/dist (deploy this folder to any static host)
node landing/build.mjs --serve    # preview on http://127.0.0.1:4173
APP_URL=https://vault.arevei.com EDGE_EXTENSION_URL=https://microsoftedge.microsoft.com/addons/detail/… node landing/build.mjs
```

## Self-hosting request form

The "Talk to us" section is a plain HTML form (no JavaScript) that posts to `APP_URL/api/v1/contact/self-host`. The API stores the request in the `selfhost_requests` table and redirects the visitor to `thanks.html`, or to `request-failed.html` if the input was invalid or rate-limited. The API finds those pages through its `LANDING_URL` setting, which defaults to `PUBLIC_ORIGIN/welcome` (the single-domain setup). Set it on the API if the landing page lives anywhere else.

When the API has SMTP configured (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_FROM_NAME`), each request is also emailed to `CONTACT_NOTIFY_TO` with `CONTACT_NOTIFY_CC` copied, and Reply-To set to the visitor so a reply goes straight to them. A failed email is logged and doesn't lose the request: the table is the record. To list them in the database:

```sql
SELECT to_timestamp(created_at) AS received, name, email, company, team_size, hosting, message
FROM selfhost_requests WHERE handled_at IS NULL ORDER BY created_at DESC;
```

## Installing the extension

A web page can't install a browser extension by itself: every browser requires the user to confirm on a store listing, or to load the files by hand. The page offers both.

- **Store buttons.** Set `EDGE_EXTENSION_URL` to the Edge Add-ons listing for an "Add to Edge" button, and `EXTENSION_URL` to the Chrome Web Store listing for "Add to Chrome". Each button is left out of the build while its variable is unset.
- **Install from GitHub.** `install-extension.html` is a five-step guide for loading the extension unpacked in Edge, Chrome or Brave. It is always built, and the landing page links to it from the setup steps and the footer. Its download button points at `EXTENSION_ZIP_URL`, which defaults to `arevei-vault-extension.zip` on the latest GitHub release. That link returns 404 until the first `v*` tag has been released.

Publishing the extension is described in [extension/README.md](../extension/README.md).

`dist/_headers` carries the security headers in the Netlify/Cloudflare Pages format. On other hosts, set the same headers yourself.

## Before launch

- Push a `v*` tag so the GitHub release exists before the install guide goes live, then publish to Edge Add-ons and set `EDGE_EXTENSION_URL`.
- Set `SMTP_PASS` on the API and submit the form once to confirm the notification email arrives.
- "Create your vault" links to `APP_URL/signup`. That only works for new founders once the hosted instance allows self-serve sign-up (`ALLOW_SIGNUP=true`).
- Add Privacy and Terms pages and link them in the footer.
- Work through the "Claims to verify before publishing" checklist in the copy doc (no audit claim, extension store links, the 10-minute setup claim).
