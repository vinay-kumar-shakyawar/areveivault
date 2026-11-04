# Arevei Vault — Threat Model

Companion to [architecture.md](architecture.md). Section references (§) point to that document.

## 1. Assets

| ID | Asset | Sensitivity |
|---|---|---|
| A1 | Item secrets: passwords, TOTP seeds, recovery codes, API keys, SSH private keys, attachments | Critical |
| A2 | Item metadata: titles, URLs, usernames, notes, client and project names | High (reveals the client list and attack surface) |
| A3 | Master password, Secret Key, AUK, ASK, private keys, vault keys | Critical (unlocks A1 and A2) |
| A4 | Account authentication: OPAQUE records, account 2FA seeds, sessions | High |
| A5 | Access graph: who can access which vault | Medium (visible to the server by design) |
| A6 | Audit log integrity | High (needed for incident response and accountability) |
| A7 | Availability of the vault and backups | High |

## 2. Trust boundaries

1. **Client ↔ server.** The server is *untrusted for confidentiality* and *trusted for availability and access enforcement*.
2. **Vault origin ↔ other web origins** (phishing sites, sites with autofill targets).
3. **Extension trusted contexts** (service worker, extension pages) **↔ content scripts ↔ page main world.**
4. **The web app code delivery path.** Code comes from the server on every load.
5. **User ↔ user** within an org (members, admins, departed members).
6. **Device ↔ OS** (memory, clipboard, disk, biometrics).

## 3. Security invariants (each one is tested)

- **I1.** No plaintext A1/A2 and no A3 ever reaches the server (canary DB-dump test).
- **I2.** No key can decrypt a ciphertext placed under a different object, vault, or version slot (associated-data binding, property tests).
- **I3.** The content script never receives a credential whose match rule doesn't match the browser-reported frame origin.
- **I4.** No autofill happens without a user gesture.
- **I5.** Clients refuse KDF parameters below the floor.
- **I6.** A vault key is never wrapped to a public key without a valid membership certificate.
- **I7.** Audit chain verification passes and detects any modified, inserted, or deleted entry.

## 4. Attackers, threats, and mitigations

### T1. Compromised server or malicious operator (DB, API, and storage access)
| Threat | Mitigation | Residual risk |
|---|---|---|
| Read vault data from the DB | All of A1/A2 encrypted client-side (§5, §7) | Metadata leaks: counts, sizes (padded), timestamps, the access graph |
| Offline-crack master passwords from a DB dump | 2SKD: guesses also need the 128-bit Secret Key (§4.2); Argon2id | None practical if the Secret Key stays off the server |
| Downgrade KDF parameters | Client-enforced floor; params bound into the keyset's associated data (§4.2) | — |
| Swap ciphertexts between items or vaults | Associated data binds org, vault, item, version, and key version (§5) | — |
| Roll back items or vaults to old versions | Client high-water marks + version in the associated data (§10) | First-time devices can't detect rollback. Deletion and withholding are possible (availability). |
| Substitute a member's public key to receive vault keys | Membership certificates signed by the org key; pinned org root (§8.2) | TOFU: a server compromised *before* a member's first login could pin a fake root. Out-of-band fingerprint check closes this. |
| Inject a fake vault so users store secrets in it | Grants must be signed by a certified member; the UI shows the grantor (§8.2) | — |
| Forge or erase audit entries | Hash chain, insert-only DB role, signed checkpoints in WORM storage and on Owner devices (§11) | Entries in the current, uncheckpointed hour can be altered by a full server compromise |
| **Serve malicious JavaScript** | See T2 | See T2 |

### T2. Malicious JavaScript delivery (compromised origin, CI, or dependency)
| Threat | Mitigation | Residual risk |
|---|---|---|
| Modified bundle captures the master password and keys | Reproducible builds + signed published hashes; the extension verifies the served build; the extension and iOS app are the high-assurance clients; org policy can forbid web unlock for admins (§12.3) | **A user who unlocks in the plain web app without the extension can't detect a targeted malicious bundle.** This is inherent to web-delivered crypto and is documented for users. |
| Third-party script or CDN compromise | None used; CSP `script-src 'self'`; SRI | — |
| Malicious npm or crate dependency (supply chain) | Lockfiles, `cargo deny`, `pnpm audit`, minimal dependency set, Renovate with human review, no install scripts (`pnpm` `ignore-scripts` with an allow-list) | A malicious upstream release that slips through review. Reproducible builds make it detectable after the fact, not preventable. |
| XSS from attacker-authored item content (shared notes, imported CSVs) | No HTML rendering of user content; structured rich text; Trusted Types; CSP (§12.1) | — |

### T3. Phishing sites
| Threat | Mitigation | Residual risk |
|---|---|---|
| A lookalike domain tricks autofill | eTLD+1 matching with the PSL private section; confusables, Punycode, and edit-distance lookalike detection; no fill on lookalikes (§13.3) | The user can still type or paste a password manually. The warning UI helps. |
| Autofill on page load harvests credentials | Never autofill without a gesture (I4) | — |
| Hidden or invisible forms capture filled values | Visibility checks; fill only visible fields | Sophisticated CSS tricks. Covered by e2e fixtures and needs ongoing maintenance. |
| Clickjacking the inline menu (transparent overlays) | Content in an extension-origin iframe; visibility and opacity checks; click refused while obscured (§13.1) | Novel bypasses. Covered by the audit (§21). |
| A malicious cross-origin iframe on a legit site | No fill into cross-origin frames unless the item allows it | — |
| Plain HTTP pages or network MITM | HSTS preload for the vault; warning and confirmation before filling on HTTP | — |
| Phishing for the master password with a fake vault login page | Passkeys/WebAuthn for account 2FA (phishing-resistant); the extension flags non-`vault.arevei.com` pages that imitate the unlock UI | A user who types the master password **and** Secret Key **and** a TOTP code into a fake page loses them. WebAuthn as 2FA is strongly recommended. |
| Account 2FA phishing | Offer WebAuthn and recommend it; TOTP is allowed but discouraged for admins | TOTP is phishable in real time |

### T4. Malicious or compromised browser extensions
| Threat | Mitigation | Residual risk |
|---|---|---|
| Another extension with `<all_urls>` reads the vault web app's DOM | Can't be stopped by a web page. Minimize what's in the DOM (reveal on demand); recommend the extension or iOS app; Chrome policy allow-lists extensions on Arevei machines | **High.** A malicious extension with host access to `vault.arevei.com` can read anything the web app renders and capture typed passwords. Org extension allow-listing is the real control. |
| Another extension reads filled credentials on third-party sites | Out of our control once filled | Same as above |
| Another extension messages our extension | No `externally_connectable` for extensions; `onMessageExternal` accepts only the vault origin with lock-signal messages | — |
| Page JavaScript reads the inline menu | Cross-origin extension iframe | — |

### T5. Stolen or unattended laptop with the browser open
| Threat | Mitigation | Residual risk |
|---|---|---|
| Vault left unlocked | Auto-lock after 5 min idle, on OS lock or idle (`idle` API), and on browser close | Within the idle window the attacker has full access |
| Read keys from disk | Keys are memory-only; disk holds ciphertext plus a non-extractable WebCrypto-wrapped Secret Key | A cold-boot or memory-forensics attack on a running, unlocked machine |
| Restored browser session | Keys never persist; restored session cookies have server-side idle and absolute timeouts; unlock still needs the master password | — |
| Clipboard leftovers | 30 s auto-clear | OS clipboard history keeps copies (documented) |
| Lost device later | Devices can be revoked remotely (sessions killed); the master password is still required | A device that's offline and unlocked |

### T6. Malicious insider
| Insider | Threat | Mitigation | Residual risk |
|---|---|---|---|
| Member | Exfiltrates the credentials they can access | Least privilege per project; audit log; copy-only flag (policy only) | **Can't be prevented cryptographically.** Detection via audit, deterrence by policy. |
| Departed member | Uses cached keys or credentials | Sessions revoked; vault key rotated; offboarding report drives **credential rotation at the source** (§8.3) | Credentials not yet rotated remain usable |
| Admin | Reads someone's Personal Vault | Personal Vault Key is wrapped only by the user's ASK; no escrow by default (§9) | With the opt-in escrow enabled, admins can |
| Admin | Abuses recovery to take over an account | Recovery notifies the user by email at every step, is audit-logged, and gives access to *shared* projects only (which the admin can already read) | — |
| Server operator | See T1 and T2 | — | — |

### T7. Other attackers
| Attacker | Threat | Mitigation |
|---|---|---|
| Online guesser | Credential stuffing or brute force | OPAQUE (no password-equivalent sent), mandatory 2FA, per-account/IP/subnet rate limits, lockout with email alerts |
| Account enumeration | Probe which emails exist | Fake salts and OPAQUE fake records; uniform responses and timing |
| CSRF / session theft | Session misuse | `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, custom header + Origin check, session bound to the device |
| Cross-tenant leakage (multi-tenant) | One org reads another org's ciphertext | API authorization + Postgres RLS + ACL matrix tests |
| Backup theft | Offline attack | Backups contain ciphertext only, are additionally `age`-encrypted, and 2SKD still applies |
| CSV formula injection | Plaintext export opened in Excel runs formulas | Cell escaping on export (§15) |
| Privacy leaks to third parties | URLs leaked to icon services, telemetry | No favicon fetching, no telemetry; HIBP uses k-anonymity with padding and is opt-in |

## 5. Out of scope (explicitly accepted)

- A fully compromised endpoint OS (keyloggers, memory scrapers) while the vault is unlocked.
- Coercion of a user to unlock their vault.
- Side channels in browser JavaScript engines beyond what constant-time Rust/WASM code gives us.
- Traffic analysis of sync timing.
