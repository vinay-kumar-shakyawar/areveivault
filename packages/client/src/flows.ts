/**
 * Account flows shared by the web app and the extension. All key material stays
 * inside the engine; these functions only shuttle opaque protocol messages and
 * ciphertext between the engine and the API.
 */

import { Api, Session } from "./api";
import { Engine, nowSecs } from "./engine";

export interface SignupInput {
  email: string;
  password: string;
  inviteToken?: string | null;
  /** Create a new organization (bootstrap / first user). */
  createOrg: boolean;
}

export interface SignupPending {
  secretKey: string;
  userId: string;
  pendingToken: string;
  totpSecret: string;
  otpauthUri: string;
}

const uuid = () => crypto.randomUUID();

export async function signup(engine: Engine, api: Api, input: SignupInput): Promise<SignupPending> {
  const email = input.email.trim().toLowerCase();
  const { secret_key: secretKey } = await engine.call<{ secret_key: string }>("generate_secret_key");
  const params = await engine.call<{ salt: string; kdf: any }>("new_account_params");
  await engine.call("derive", { password: input.password, secret_key: secretKey, salt: params.salt, kdf: params.kdf });

  const reg = await engine.call<{ message: string }>("opaque_register_start");
  const start = await api.registerStart({ email, invite_token: input.inviteToken ?? null, registration_request: reg.message });
  const fin = await engine.call<{ upload: string }>("opaque_register_finish", { response: start.registration_response });

  const userId = uuid();
  const account = await engine.call<{ keyset: any; org_bootstrap: any }>("create_account", {
    user_id: userId,
    email,
    salt: params.salt,
    kdf: params.kdf,
    create_org_id: input.createOrg ? uuid() : null,
    now: nowSecs(),
  });
  const done = await api.registerFinish({
    signup_token: start.signup_token,
    user_id: userId,
    registration_upload: fin.upload,
    keyset: account.keyset,
    org_bootstrap: account.org_bootstrap ?? undefined,
  });
  return { secretKey, userId, pendingToken: done.pending_token, totpSecret: done.totp_secret, otpauthUri: done.otpauth_uri };
}

export interface LoginStep1 {
  mfaToken: string;
  methods: string[];
}

/** OPAQUE login. Throws ApiError(401) or EngineError on wrong password / Secret Key. */
export async function loginPassword(
  engine: Engine,
  api: Api,
  email: string,
  password: string,
  secretKey: string,
): Promise<LoginStep1> {
  email = email.trim().toLowerCase();
  const pre = await api.prelogin(email);
  await engine.call("derive", { password, secret_key: secretKey, salt: pre.salt, kdf: pre.kdf });
  const start = await engine.call<{ message: string }>("opaque_login_start");
  const s = await api.loginStart({ email, credential_request: start.message });
  const fin = await engine.call<{ finalization: string }>("opaque_login_finish", { response: s.credential_response });
  const f = await api.loginFinish({ login_token: s.login_token, credential_finalization: fin.finalization });
  return { mfaToken: f.mfa_token, methods: f.methods };
}

/** After MFA: fetch the keyset and unlock with the AUK derived during login. */
export async function completeLogin(engine: Engine, api: Api): Promise<void> {
  const keyset = await api.keyset();
  await engine.call("unlock", { keyset });
}

/** Local unlock (session still valid): re-derive from cached keyset, no server round trip needed. */
export async function unlockLocal(engine: Engine, keyset: any, password: string, secretKey: string): Promise<void> {
  await engine.call("derive", { password, secret_key: secretKey, salt: keyset.salt, kdf: keyset.kdf });
  await engine.call("unlock", { keyset });
}

export type { Session };
