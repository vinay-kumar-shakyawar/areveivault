# Landing page

The static marketing page for Arevei Vault, positioned for solo founders. The copy comes from the "Arevei Vault — Landing Page Copy (Solo Founders)" doc.

- No JavaScript, no third-party requests. It ships under `default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:`, plus `form-action` for the one form below.
- Colors come from `packages/ui/src/tokens.css`, the same tokens as the app. Dark by default, and it follows the system light/dark setting.
- Fonts are self-hosted from the web app's `@fontsource` packages, so run `pnpm install` first.

```bash
node landing/build.mjs            # → landing/dist (deploy this folder to any static host)
node landing/build.mjs --serve    # preview on http://127.0.0.1:4173
APP_URL=https://vault.arevei.com EXTENSION_URL=https://chromewebstore.google.com/detail/… node landing/build.mjs
```

## Self-hosting request form

The "Talk to us" section is a plain HTML form (no JavaScript) that posts to `APP_URL/api/v1/contact/self-host`. The API stores the request in the `selfhost_requests` table and redirects the visitor to `thanks.html`, or to `request-failed.html` if the input was invalid or rate-limited. The API finds those pages through its `LANDING_URL` setting, which defaults to `PUBLIC_ORIGIN/welcome` (the single-domain setup). Set it on the API if the landing page lives anywhere else.

When the API has SMTP configured (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_FROM_NAME`), each request is also emailed to `CONTACT_NOTIFY_TO` with `CONTACT_NOTIFY_CC` copied, and Reply-To set to the visitor so a reply goes straight to them. A failed email is logged and doesn't lose the request: the table is the record. To list them in the database:

```sql
SELECT to_timestamp(created_at) AS received, name, email, company, team_size, hosting, message
FROM selfhost_requests WHERE handled_at IS NULL ORDER BY created_at DESC;
```

## "Add to Chrome" button

A web page can't install a browser extension by itself: Chrome removed inline installation in 2018, and every browser now requires the user to confirm on the store listing. The closest thing is a button that opens the listing, where the visitor clicks "Add to Chrome" once. Set `EXTENSION_URL` to the Chrome Web Store listing and the buttons appear; while it's unset they're left out of the build. Publishing the extension is described in [extension/README.md](../extension/README.md).

`dist/_headers` carries the security headers in the Netlify/Cloudflare Pages format. On other hosts, set the same headers yourself.

## Before launch

- Publish the extension and set `EXTENSION_URL`.
- Set `SMTP_PASS` on the API and submit the form once to confirm the notification email arrives.
- "Create your vault" links to `APP_URL/signup`. That only works for new founders once the hosted instance allows self-serve sign-up (`ALLOW_SIGNUP=true`).
- Add Privacy and Terms pages and link them in the footer.
- Work through the "Claims to verify before publishing" checklist in the copy doc (no audit claim, extension store links, the 10-minute setup claim).
