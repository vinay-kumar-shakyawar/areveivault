# Landing page

The static marketing page for Arevei Vault, positioned for solo founders. The copy comes from the "Arevei Vault — Landing Page Copy (Solo Founders)" doc.

- No JavaScript, no third-party requests. It ships under `default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:`.
- Colors come from `packages/ui/src/tokens.css`, the same tokens as the app. Dark by default, and it follows the system light/dark setting.
- Fonts are self-hosted from the web app's `@fontsource` packages, so run `pnpm install` first.

```bash
node landing/build.mjs            # → landing/dist (deploy this folder to any static host)
node landing/build.mjs --serve    # preview on http://127.0.0.1:4173
APP_URL=https://vault.arevei.com SELF_HOST_GUIDE_URL=https://… node landing/build.mjs
```

`dist/_headers` carries the security headers in the Netlify/Cloudflare Pages format. On other hosts, set the same headers yourself.

## Before launch

- Set `SELF_HOST_GUIDE_URL` to the public setup guide. It defaults to the on-page `#self-host` section.
- "Create your vault" links to `APP_URL/signup`. That only works for new founders once the hosted instance allows self-serve sign-up (`ALLOW_SIGNUP=true`).
- Add Privacy and Terms pages and link them in the footer.
- Work through the "Claims to verify before publishing" checklist in the copy doc (no audit claim, extension store links, the 10-minute setup claim).
