# Threat Model: `@brainwebuk/payload-plugin-mcp-oauth`

**Method:** STRIDE  
**Date:** 2026-06-04  
**References:** ADR-0001 through ADR-0005, OWASP OAuth cheat sheet, OAuth 2.1 BCP

---

## 1. Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| OAuth access tokens (plaintext) | Critical — grants MCP access | In-flight only; never stored |
| OAuth refresh tokens (plaintext) | Critical — long-lived session | In-flight only; never stored |
| Authorization codes (plaintext) | High — short-lived, single-use | In-flight only; never stored |
| Token hashes | Medium — not redeemable but confirm existence | `oauth-tokens` collection |
| Token pepper (`PMOAUTH_TOKEN_PEPPER`) | Critical — protects all token hashes | Environment variable |
| Payload secret | Critical — used by upstream API-key flow | Environment variable |
| User credentials | Critical | Managed by Payload core, not this plugin |
| OAuth client records | Low | `oauth-clients` collection |
| Authorization code records | Medium (pre-consumption) | `oauth-auth-codes` collection |
| Payload admin session cookies | High — gates consent screen | HTTP-only, same-site; managed by Payload |

---

## 2. Trust boundaries

```
[MCP client (Claude.ai)]
        │ HTTPS
        ▼
[HTTP edge — TLS termination]
        │
        ▼
[Payload server / Next.js process]
  ├── OAuth endpoints (this plugin)
  ├── MCP endpoint (upstream plugin, wrapped by this plugin)
  └── Payload admin (consent screen, session)
        │
        ▼
[Database — SQLite / Postgres]
  ├── oauth-tokens
  ├── oauth-auth-codes
  ├── oauth-clients
  └── payload-mcp-api-keys (upstream)
```

Trust boundaries crossed on each request:
- **B1:** Internet → HTTP edge (TLS required in production)
- **B2:** HTTP edge → Payload process (loopback or internal network)
- **B3:** Payload process → Database (local file or TCP with auth)

---

## 3. STRIDE analysis

### 3.1 Spoofing

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| S1 | Attacker presents a forged or guessed access token | Tokens are 256 bits of cryptographic entropy; brute-force is computationally infeasible (2^256 space). HMAC validation on every request. | T2.4, T3.5 |
| S2 | Attacker replays a captured access token before expiry | Access tokens have a 60-minute TTL. Revocation via `POST /api/oauth/revoke` takes effect immediately. Short TTL limits the replay window. | T2.3, T4.7 |
| S3 | Attacker replays a captured refresh token | Refresh tokens are single-use with rotation. A consumed token triggers family revocation on next use. | T3.4 |
| S4 | Attacker spoofs a registered client (misuses another client's `client_id`) | Client has no secret, but PKCE verifier must match the challenge stored at authorize time. An attacker without the verifier cannot exchange the auth code. | T3.2, T4.4 |
| S5 | Attacker intercepts an auth code in the redirect | `state` is RECOMMENDED per OAuth 2.1 + PKCE (the primary CSRF defence is PKCE, not state). The server echoes state unchanged; the client verifies it. PKCE binds the code to the originating client. HTTPS required in production. | T4.4, T4.5 |

### 3.2 Tampering

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| T1 | Attacker tampers with `redirect_uri` in authorize request to redirect auth code to attacker-controlled URL | Exact-match validation of `redirect_uri` against registered URIs (ADR-0003 §6). Any mismatch returns `invalid_request`, no redirect issued. | T4.4 |
| T2 | Attacker tampers with `scope` to elevate privileges | **Scope is a privilege boundary, and it only ever narrows.** A requested scope is validated against the operator-enabled capabilities at `/authorize`, re-validated at `/consent` (so tampering with the hidden form field is caught), and resolved again when the code is redeemed. `scopeToCapabilities` grants a scope token only if *every* operation it names is enabled on the server — no partial widening — and a single unknown, malformed or disabled token rejects the whole grant with `invalid_scope`. Tampering can therefore only ask for less, or for nothing. An omitted scope is the RFC 6749 §3.3 pre-defined default: the full operator grant, stated as such on the consent screen. | T4.4 |
| T3 | Attacker tampers with `state` parameter to break CSRF binding | `state` is opaque to the server and RECOMMENDED but optional (per OAuth 2.1 §2.1.2; PKCE is the primary CSRF defence). The server echoes state unchanged; the client verifies it on receipt. Absent state is not rejected — clients relying on state alone for CSRF protection must send it. | T4.4 |
| T4 | Database row tampering — attacker with DB access modifies token capabilities | All tokens store a HMAC-protected hash. Modifying a row does not create a valid token. However, direct DB write with a known pepper could. Mitigation: restrict DB access; pepper stored separately from DB. | T2.4, T8.3 |
| T5 | Attacker modifies `code_challenge` after it is stored to accept their own verifier | `code_challenge` is written once on authorize and compared at token exchange. No update path exists. | T2.2 |

### 3.3 Repudiation

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| R1 | User denies approving a client | Consent approval is logged with `user_id`, `client_id`, `scope`, `auth_code_id`, and timestamp. | T8.2 |
| R2 | Client denies registering or making requests | Registration events, token issues, and revocations are all logged with `client_id`, `ip`, and `user_agent`. | T8.2 |
| R3 | Admin denies revoking a token | Revocation happens on the native `oauth-tokens` collection (set `revokedAt`, or delete the row) or via `POST /api/oauth/revoke`. Both run through the collection's `afterChange` hooks (cascade revocation) and are subject to Payload's standard admin action auditing; the revoke endpoint logs `client_id`/`ip`/`user_agent` (T8.2). | T8.2 |

### 3.4 Information disclosure

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| I1 | Token plaintext leaked in logs | Logging utilities (T8.2) never log Bearer headers, token values, code values, or PKCE verifiers. Only hashed IDs appear in logs. | T8.2 |
| I2 | Stack traces or DB internals returned in error responses | All error responses are RFC 6749-compliant JSON (`{"error": "...", "error_description": "..."}`) with no internal details. A global error handler catches unhandled exceptions. | T4.3–T4.7 |
| I3 | Token hash exposed if DB is compromised | Hashes are HMAC-SHA-256 with a server-side pepper. Without the pepper, hashes are not redeemable. | T2.4, T8.3 |
| I4 | Timing oracle on token lookup (reveals whether a token exists) | `validateAccessToken` locates tokens via an indexed DB equality query on the HMAC hash — the DB lookup itself is not constant-time and the not-found branch does not pad to match the found-branch timing. The actual hash comparison uses `crypto.timingSafeEqual`. Real impact is negligible: the looked-up value is an unguessable 256-bit HMAC, so a timing side-channel reveals no actionable information to an attacker. | T2.4, T3.5 |
| I5 | `client_id` enumeration via registration errors | Registration errors are returned as RFC 7591 errors without revealing whether a `client_id` already exists. | T4.3 |
| I6 | Consent screen leaks OAuth parameters in Referrer header | `Referrer-Policy: strict-origin-when-cross-origin` on consent screen. Form action is same-origin. | T6.1, T8.1 |
| I7 | Auth code exposed in browser history or server logs via GET request | Auth codes are delivered as query parameters on redirects (per RFC 6749 §4.1.2). To mitigate: the redirect uses 302 (not 301, avoiding caching), and auth code records are deleted after consumption. HTTPS in production prevents interception. **Accepted risk:** query-parameter delivery is the RFC-standard mechanism; fragment delivery is not universally supported by MCP clients. | Accepted |

### 3.5 Denial of Service

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| D1 | Flood of registration requests filling `oauth-clients` collection | Per-IP rate limiting on `/register` (T4.8). Inactive/unused clients can be pruned by admin. | T4.8 |
| D2 | Flood of authorize requests creating pending sessions | Per-IP rate limiting on `/authorize` (T4.8). Pending authorize sessions are short-lived (10 minutes). | T4.8 |
| D3 | Flood of token requests | Per-IP rate limiting on `/token` (T4.8). The rate-limit key is the client IP **alone** — a client-supplied identifier is never mixed in, because rotating it would mint a fresh bucket per request and defeat the per-IP limit. IP is taken from `x-forwarded-for` (see §6). | T4.8 |
| D4 | Large-scale auth code creation exhausting DB | Auth codes expire in 60 seconds; a sweep hook purges expired records. Rate limiting bounds the creation rate. | T2.2, T4.8 |
| D5 | Token validation becomes a bottleneck at high MCP RPS | HMAC-SHA-256 lookup is O(log n) on an indexed `token_hash` column. T7.8 benchmarks the path to confirm p95 < 25 ms. | T2.3, T7.8 |
| D6 | Attacker triggers refresh-token family revocation to lock out legitimate user | If an attacker uses a stolen refresh token, family revocation runs — the legitimate user is also logged out. **Accepted risk:** this is the correct security outcome per OAuth 2.1 BCP §2.2.2. The user must re-authorize, which is a minor inconvenience compared to an active attacker using the session. | Accepted |

### 3.6 Elevation of Privilege

| # | Threat | Mitigation | Task |
|---|--------|------------|------|
| E1 | OAuth token used to access a collection capability beyond what the operator enabled | `MCPAccessSettings` is built at validation time by **intersecting** the token's stored grant with the capabilities enabled on the MCP server *at that moment* (`buildFullCapabilities(mcpPluginOptions)`), never from the client's registration or self-asserted claims. The live config is therefore a hard ceiling a token can never exceed, and disabling a collection (or a single operation on it) narrows every existing token on the next request rather than when the last token issued before the change expires. Tokens also record the grant they were issued with, so a row is auditable on its own — up to 0.4.0 an omitted scope stored `{}`, which read as “no permissions” while requests ran with full access (#75). | T3.5, T4.5 |
| E2 | Attacker uses another user's access token | Tokens are bound to a `user_id`. Token validation returns the stored user, not the requesting party. The MCP handler uses `mcpAccessSettings.user` for all operations. | T3.5 |
| E3 | PKCE downgrade — attacker convinces client to use `plain` method | Only `S256` is accepted. Any request with `code_challenge_method=plain` (or absent, or any other value) returns `invalid_request` immediately. | T3.2, T4.4 |
| E4 | IDOR — non-admin views or revokes another user's tokens via the admin UI | The `oauth-clients` and `oauth-tokens` collections are operator-only management surfaces gated by the configurable `adminAccess` rule (`read`/`update`/`delete`; `create` always denied). The default authorises **only** authenticated members of the admin `userCollection` and denies the entire public REST/GraphQL surface. **Operator responsibility:** if `userCollection` mixes admins with untrusted end-users, the operator MUST supply a role-scoped `adminAccess` (documented in the README) — otherwise any such user could read others' tokens. End-users never reach these collections in the default operator-only deployment. | T5.5 |
| E5 | IDOR — user reads or modifies another user's auth code records | The `oauth-auth-codes` collection has admin-only read access in the Payload admin. Code consumption validates `user_id` match. | T2.2, T4.6 |
| E6 | Attacker registers a client with a malicious `client_name` for XSS on consent screen | `client_name` is HTML-escaped before rendering on the consent screen. Content-Security-Policy blocks inline scripts. | T4.3, T6.1 |
| E7 | Open redirect via `redirect_uri` manipulation | Exact-match redirect URI validation (ADR-0003 §6). Any non-exact match is rejected with `invalid_request` before any redirect occurs. | T4.4 |
| E8 | CSRF on consent form submission | `POST /api/oauth/consent` is **session-bound**: it requires an authenticated Payload session (`req.user`) and mints the auth code for the *session* user, never the body-supplied `user_id` (a mismatched `user_id` is rejected). The form's CSRF token is a **time-bound** HMAC over `(userId, clientId, redirectUri, codeChallenge, issuedAt)`, bound to the session user and rejected once older than 10 minutes. **Known limitation:** the token is not yet single-use; within the 10-minute TTL the same consent form could be submitted more than once, creating duplicate auth codes for the same user+client+challenge. Impact is low: same-site cookies block cross-origin submissions, PKCE binds codes to the originating client, and auth codes are themselves single-use. Tracked as enhancement #27. | T4.5 |
| E9 | Auth code injection — attacker injects a valid code obtained from another flow | Auth codes are bound to `client_id`, `redirect_uri`, and PKCE challenge. All three must match at exchange time. | T4.6 |
| E10 | Attacker calls admin-only collection endpoints directly via REST | `oauth-clients`, `oauth-auth-codes`, `oauth-tokens` collections use Payload access control set to admin-only. No public REST/GraphQL access to these collections. | T2.1–T2.3 |

---

## 4. Out-of-scope threats (accepted risks)

| Threat | Justification |
|--------|---------------|
| Compromise of the host server | Outside the plugin's responsibility. Deployers must secure the server. |
| Compromise of the database file/server | Mitigated by pepper separation (ADR-0002 §4) but a direct DB write with the pepper bypasses token validation. This is an accepted risk inherent to any server-side auth system. |
| TLS interception at the network level | HTTPS is required in production (T8.3 enforces this at boot). Certificate pinning is out of scope. |
| Malicious Payload plugins in the same process | Plugins run in the same Node.js process and can, in principle, access any in-memory data. This is a constraint of the Payload plugin model, not specific to this plugin. |
| Auth code interception via Referer header leakage | Auth codes are in query parameters, which could appear in Referer headers to third-party resources on the callback page. The MCP client's callback page is responsible for not loading third-party resources before consuming the code. **Accepted** as a client responsibility. |

---

## 5. Cross-cutting mitigations

These mitigations apply to the entire plugin, not a single threat:

| Control | Description | Tasks |
|---------|-------------|-------|
| HTTPS required | Boot check refuses to start in production without `NEXT_PUBLIC_SERVER_URL` starting with `https://`. | T8.3 |
| Security headers | `Cache-Control: no-store`, `Strict-Transport-Security`, and `X-Content-Type-Options` on all JSON OAuth responses (`jsonResponse`). Consent/authorize HTML also adds `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` (NOT `no-referrer` — that makes browsers send `Origin: null` on the consent POST, which Payload rejects → 401; see row I6), and a strict CSP. | T8.1 |
| No-store cache headers | `Cache-Control: no-store` on all token and auth code responses. | T8.1 |
| Rate limiting | Per-IP limits on all public OAuth endpoints. The key is the client IP **alone** (`ip:<ip>`); a client-supplied identifier (`client_id` / `client_name`) is deliberately never part of the key, since rotating it would mint a fresh bucket and bypass the per-IP limit. IP is taken from `x-forwarded-for`; operators behind a reverse proxy should ensure only one trusted proxy sets this header. | T4.8 |
| Audit logging | Structured log entries for all significant auth events, with no secret material. | T8.2 |
| Semgrep + CodeQL | Automated SAST in CI catches common injection and logic vulnerabilities. | T0.5 |
| gitleaks | Secret scanning in CI prevents accidental key commits. | T0.5 |
| Dependency audit | `pnpm audit` in CI fails on high/critical CVEs. | T0.5 |
| PKCE S256 only | `plain` method universally rejected. No configuration option to enable it. | T3.2 |
| Constant-time comparisons | All token hash comparisons use `crypto.timingSafeEqual`. | T2.4, T3.5 |
