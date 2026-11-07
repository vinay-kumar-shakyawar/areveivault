/** Typed client for the Arevei Vault API (docs/api.md). Carries only ciphertext. */

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public body?: any,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface ApiOptions {
  /** e.g. "https://vault.arevei.com" for the extension; "" for same-origin web app. */
  baseUrl: string;
  /** Extension uses a bearer token; the web app relies on the HttpOnly cookie. */
  getToken?: () => string | null | Promise<string | null>;
  onUnauthorized?: () => void;
  /**
   * Called once per request the first time it is retried because the gateway reported the API
   * unavailable (502/503/504), e.g. a Render free instance waking from spin-down. Lets the UI say
   * "waking up the server" instead of surfacing the transient error.
   */
  onWaking?: () => void;
}

/** Gateway statuses that mean "the API did not answer", which is safe to retry: no handler ran. */
const WAKING_STATUSES = new Set([502, 503, 504]);
/** Backoff between retries (ms). Sums to ~56s, which covers a Render free-tier cold start. */
const WAKING_DELAYS = [1000, 2000, 3000, 5000, 5000, 8000, 8000, 8000, 8000, 8000];
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface Session {
  user_id: string;
  email: string;
  org_id: string | null;
  role: "owner" | "admin" | "member";
  status: "active" | "pending_approval";
  device_id: string;
}

export interface KeyGrant {
  keyring_id: string;
  key_version: number;
  recipient_id: string;
  grantor_id: string;
  wrapped: string;
  signature: string;
}

export interface ItemWrite {
  id: string;
  vault_id: string;
  version: number;
  key_version: number;
  wrapped_key: string;
  payload: string;
  expected_version: number | null;
}

export class Api {
  constructor(private opts: ApiOptions) {}

  async request<T = any>(method: string, path: string, body?: unknown, raw = false): Promise<T> {
    const headers: Record<string, string> = { "X-Arevei-Request": "1" };
    const token = await this.opts.getToken?.();
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload: BodyInit | undefined;
    if (body instanceof Uint8Array) {
      headers["Content-Type"] = "application/octet-stream";
      payload = body as unknown as BodyInit;
    } else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const url = `${this.opts.baseUrl}/api/v1${path}`;
    const init: RequestInit = {
      method,
      headers,
      body: payload,
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    };
    let res = await fetch(url, init);
    // A 502/503/504 comes from the proxy in front of the API, not from the API itself, so the
    // request never reached a handler and can be repeated. This mostly happens while the backend
    // host wakes a spun-down instance; keep retrying for about a minute before giving up.
    for (let attempt = 0; WAKING_STATUSES.has(res.status) && attempt < WAKING_DELAYS.length; attempt++) {
      if (attempt === 0) this.opts.onWaking?.();
      await sleep(WAKING_DELAYS[attempt]);
      res = await fetch(url, init);
    }
    if (res.status === 401) this.opts.onUnauthorized?.();
    if (!res.ok) {
      let data: any = {};
      try {
        data = await res.json();
      } catch {
        /* non-JSON error */
      }
      throw new ApiError(res.status, data.error ?? "error", data.message ?? res.statusText, data);
    }
    if (res.status === 204) return undefined as T;
    if (raw) return new Uint8Array(await res.arrayBuffer()) as T;
    return (await res.json()) as T;
  }

  // ---- auth ----
  prelogin = (email: string) => this.request<{ salt: string; kdf: any }>("POST", "/auth/prelogin", { email });
  registerStart = (b: { email: string; invite_token?: string | null; registration_request: string }) =>
    this.request<{ registration_response: string; signup_token: string }>("POST", "/auth/register/start", b);
  registerFinish = (b: {
    signup_token: string;
    user_id: string;
    registration_upload: string;
    keyset: unknown;
    org_bootstrap?: unknown;
  }) => this.request<{ pending_token: string; totp_secret: string; otpauth_uri: string }>("POST", "/auth/register/finish", b);
  confirmTotp = (b: { pending_token: string; code: string; device_name: string }) =>
    this.request<Session & { session_token: string }>("POST", "/auth/mfa/totp/confirm", b);
  loginStart = (b: { email: string; credential_request: string }) =>
    this.request<{ credential_response: string; login_token: string }>("POST", "/auth/login/start", b);
  loginFinish = (b: { login_token: string; credential_finalization: string }) =>
    this.request<{ mfa_token: string; methods: string[] }>("POST", "/auth/login/finish", b);
  verifyMfa = (b: { mfa_token: string; code: string; device_name: string }) =>
    this.request<Session & { session_token: string }>("POST", "/auth/mfa/verify", b);
  logout = () => this.request<void>("POST", "/auth/logout");
  session = () => this.request<Session>("GET", "/auth/session");

  // ---- account ----
  keyset = () => this.request<any>("GET", "/keyset");
  getPrefs = () => this.request<{ blob: string | null }>("GET", "/prefs");
  putPrefs = (blob: string) => this.request<{ blob: string }>("PUT", "/prefs", { blob });
  devices = () => this.request<any[]>("GET", "/devices");
  revokeDevice = (id: string) => this.request<void>("DELETE", `/devices/${encodeURIComponent(id)}`);

  // ---- sync ----
  sync = (since: number) => this.request<any>("GET", `/sync?since=${since}`);

  // ---- items ----
  putItem = (w: ItemWrite) => this.request<any>("PUT", `/items/${encodeURIComponent(w.id)}`, w);
  deleteItem = (id: string, purge = false) =>
    this.request<void>("DELETE", `/items/${encodeURIComponent(id)}${purge ? "?purge=true" : ""}`);
  restoreItem = (id: string) => this.request<any>("POST", `/items/${encodeURIComponent(id)}/restore`);

  // ---- clients / vaults ----
  createClient = (b: { id: string; name_enc: string }) => this.request<any>("POST", "/clients", b);
  updateClient = (id: string, name_enc: string) => this.request<any>("PUT", `/clients/${id}`, { name_enc });
  deleteClient = (id: string) => this.request<void>("DELETE", `/clients/${id}`);
  createVault = (b: unknown) => this.request<any>("POST", "/vaults", b);
  updateVault = (id: string, name_enc: string) => this.request<any>("PUT", `/vaults/${id}`, { name_enc });
  deleteVault = (id: string) => this.request<void>("DELETE", `/vaults/${id}`);
  vaultMembers = (id: string) => this.request<{ user_id: string; role: string; copy_only: boolean }[]>("GET", `/vaults/${id}/members`);
  putVaultMember = (id: string, userId: string, b: { role: string; copy_only: boolean; grant: KeyGrant | null }) =>
    this.request<any>("PUT", `/vaults/${id}/members/${userId}`, b);
  removeVaultMember = (id: string, userId: string) => this.request<void>("DELETE", `/vaults/${id}/members/${userId}`);
  rotateVault = (id: string, b: unknown) => this.request<any>("POST", `/vaults/${id}/rotate`, b);

  // ---- org ----
  createInvite = (email: string, role: string) =>
    this.request<{ invite_token: string; expires_at: number }>("POST", "/org/invites", { email, role });
  invites = () => this.request<any[]>("GET", "/org/invites");
  deleteInvite = (id: string) => this.request<void>("DELETE", `/org/invites/${id}`);
  approveMember = (userId: string, b: { cert: unknown; grants: KeyGrant[] }) =>
    this.request<any>("POST", `/org/members/${userId}/approve`, b);
  updateMember = (userId: string, b: { role: string; grants?: KeyGrant[] }) =>
    this.request<any>("PATCH", `/org/members/${userId}`, b);
  offboardMember = (userId: string) => this.request<{ affected_vault_ids: string[] }>("DELETE", `/org/members/${userId}`);

  // ---- attachments ----
  putAttachment = (id: string, itemId: string, data: Uint8Array) =>
    this.request<void>("PUT", `/attachments/${id}?item_id=${encodeURIComponent(itemId)}`, data);
  getAttachment = (id: string) => this.request<Uint8Array>("GET", `/attachments/${id}`, undefined, true);
  deleteAttachment = (id: string) => this.request<void>("DELETE", `/attachments/${id}`);

  // ---- audit ----
  reportEvents = (events: AuditEventInput[]) => this.request<void>("POST", "/audit/events", { events });
  audit = (before?: number, limit = 100) =>
    this.request<any[]>("GET", `/audit?limit=${limit}${before ? `&before=${before}` : ""}`);
  auditVerify = () => this.request<any>("GET", "/audit/verify");
}

export interface AuditEventInput {
  event_type: "item_view" | "item_reveal" | "item_copy" | "autofill" | "export" | "totp_copy";
  target_type: "item" | "vault" | "org";
  target_id: string;
  vault_id?: string | null;
  client_ts: number;
}
