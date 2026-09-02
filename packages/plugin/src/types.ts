import type { Access } from 'payload'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import type { RateLimitOptions } from './middleware/rate-limit.js'

export interface PayloadMcpOAuthConfig {
  /**
   * The public base URL of the Payload instance (e.g. https://cms.example.com).
   * Used as the OAuth `issuer` and to construct all endpoint URLs in metadata.
   */
  issuer: string

  /**
   * A reference to the SAME options object passed to `mcpPlugin()`.
   * The OAuth plugin sets `overrideAuth` on this reference so that the MCP
   * handler can validate OAuth tokens at request time.
   *
   * ⚠️ This must be the exact same object reference — not a copy, spread, or
   * fresh literal. Assign it to a `const` and pass that same `const` to both
   * `mcpPlugin()` and `payloadMcpOAuth()`:
   *
   * ```ts
   * const mcpOptions: MCPPluginConfig = { collections: { ... } }
   * plugins: [
   *   mcpPlugin(mcpOptions),
   *   payloadMcpOAuth({ issuer, mcpPluginOptions: mcpOptions }),
   * ]
   * ```
   *
   * If you pass a different object, `overrideAuth` is installed on an object the
   * MCP handler never sees. Since 0.5.0 that is detected at boot and throws
   * `MCP_OPTIONS_NOT_SHARED` — previously it failed silently at runtime, with
   * OAuth tokens 401ing while the API-key path kept working.
   */
  mcpPluginOptions: MCPPluginConfig

  /**
   * Turn the OAuth layer off without uninstalling. When `true` (or when the MCP
   * plugin itself is disabled via `mcpPluginOptions.disabled`), the plugin adds
   * NO endpoints, does NO token-validation wiring, and leaves `mcpPluginOptions`
   * untouched — the MCP server keeps working with API keys only.
   *
   * The OAuth collections are still registered (they're relationally isolated, so
   * this is safe) to keep the database schema consistent for migrations — matching
   * how `@payloadcms/plugin-mcp` and the official plugin template behave.
   *
   * @default false
   */
  disabled?: boolean

  /**
   * The Payload collection that holds user accounts.
   * @default 'users'
   */
  userCollection?: string

  /**
   * Access rule deciding who may VIEW and MANAGE the OAuth collections
   * (`oauth-clients`, `oauth-tokens`) in the Payload admin UI and over the
   * Local API. This gates `read`, `update`, and `delete`; `create` is always
   * denied (clients self-register via Dynamic Client Registration and tokens
   * are minted by the token endpoint).
   *
   * The default authorises an authenticated user who **belongs to the configured
   * `userCollection`** AND passes `isOAuthAdmin` — which honours a `role`,
   * `isAdmin`, or `roles` field when the collection has one, and authorises any
   * member when it has none. The standard Payload starters (no role field) are
   * unaffected; apps that do carry roles get the tighter gate automatically.
   *
   * ⚠️ If your operators carry a role other than `admin`, this default will lock
   * them out of the OAuth screens — supply your own rule below.
   *
   * ⚠️ If your `userCollection` mixes admins with untrusted end-users (e.g. a
   * single `users` collection for both staff and customers), supply your own
   * rule here — otherwise any logged-in user could rewrite a client's
   * `redirectUris` (→ auth-code theft) or revoke others' tokens.
   *
   * @default ({ req }) => req.user?.collection === userCollection && isOAuthAdmin(req.user)
   */
  adminAccess?: Access

  /**
   * Where to send an unauthenticated user to sign in during the authorize flow,
   * as an app-absolute path (e.g. `/staff/login`).
   *
   * Defaults to your Payload admin login route, read from the config —
   * `routes.admin` joined with `admin.routes.login`, so customising either is
   * picked up automatically. Set this only if your sign-in page lives outside
   * the admin panel entirely.
   *
   * Until 0.5.0 this was hardcoded to `/admin/login`, so an app with a custom
   * admin route sent users to a 404 in the middle of the OAuth flow.
   */
  loginPath?: string

  /**
   * Lifetime of issued access tokens in seconds.
   *
   * Until 0.4.0 this value was resolved but never passed to the token endpoint,
   * so shortening it had no effect on issued credentials.
   *
   * @default 3600
   */
  accessTokenTtlSeconds?: number

  /**
   * Lifetime of issued refresh tokens in seconds.
   *
   * Applies to tokens minted by both the `authorization_code` and
   * `refresh_token` grants. Until 0.4.0 this value was resolved but never
   * passed to the token endpoint, so every deployment issued 30-day refresh
   * tokens regardless of what was configured here.
   *
   * @default 86400
   */
  refreshTokenTtlSeconds?: number

  /** Lifetime of issued auth codes in seconds. @default 300 */
  authCodeTtlSeconds?: number

  /**
   * Per-endpoint rate-limit overrides.
   *
   * ⚠️ Buckets are keyed on the first entry of the `x-forwarded-for` header.
   * That header is client-supplied unless something upstream overwrites it, so
   * these limits only hold when the app sits behind a proxy/load balancer that
   * sets `x-forwarded-for` itself. Exposed directly to the internet, a caller
   * can rotate the header to mint a fresh quota per request.
   *
   * ⚠️ Buckets live in the memory of a single process. Across several instances
   * — or on serverless, where each cold start begins empty — the effective limit
   * is the configured one multiplied by however many processes are live, and on
   * short-lived functions it may never bind at all.
   *
   * The limits are a speed bump against casual abuse, never the only control —
   * PKCE, the single-use CSRF nonce and the session gate are what actually
   * protect the flow.
   */
  rateLimits?: RateLimitOptions
}

export interface ResolvedConfig {
  issuer: string
  mcpPluginOptions: MCPPluginConfig
  userCollection: string
  adminAccess: Access
  accessTokenTtlSeconds: number
  refreshTokenTtlSeconds: number
  authCodeTtlSeconds: number
  rateLimits: RateLimitOptions
}

export class PayloadMcpOAuthError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'PayloadMcpOAuthError'
    this.code = code
  }
}

export class OAuthInvalidTokenError extends Error {
  constructor() {
    super('OAuth token validation failed')
    this.name = 'OAuthInvalidTokenError'
  }
}
