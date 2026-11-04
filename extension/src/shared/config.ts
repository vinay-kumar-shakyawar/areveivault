// Build-time constants injected by build.mjs (esbuild `define`). Assigned directly so
// esbuild constant-folds them and drops E2E-only code from release bundles.
declare const __VAULT_ORIGIN__: string;
declare const __BUNDLE_MANIFEST_URL__: string;
declare const __E2E__: boolean;
declare const __EXTRA_VAULT_ORIGINS__: string[];

export const VAULT_ORIGIN: string = __VAULT_ORIGIN__;
export const BUNDLE_MANIFEST_URL: string = __BUNDLE_MANIFEST_URL__;
export const EXTRA_VAULT_ORIGINS: string[] = __EXTRA_VAULT_ORIGINS__;
export const E2E: boolean = __E2E__;

export const DEFAULT_AUTOLOCK_MINUTES = 5;
export const CLIPBOARD_CLEAR_MS = 30_000;
export const PENDING_CAPTURE_TTL_MS = 5 * 60_000;
export const MENU_TOKEN_TTL_MS = 2 * 60_000;
export const SYNC_INTERVAL_MINUTES = 1;
