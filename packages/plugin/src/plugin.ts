import type { Access, CollectionConfig, Config, Endpoint, PayloadRequest } from 'payload'
import type { PayloadMcpOAuthConfig, ResolvedConfig } from './types.js'
import { oauthAuthCodesCollection } from './collections/auth-codes.js'
import { oauthClientsCollection } from './collections/clients.js'
import { oauthCsrfNoncesCollection } from './collections/csrf-nonces.js'
import { oauthTokensCollection } from './collections/tokens.js'
import { makeAuthorizeHandler } from './endpoints/authorize.js'
import { makeConsentHandler } from './endpoints/consent.js'
import { makeAsMetadataHandler } from './endpoints/metadata-as.js'
import { makePrmMetadataHandler } from './endpoints/metadata-prm.js'
import { makeRegisterHandler } from './endpoints/register.js'
import { makeRevokeHandler } from './endpoints/revoke.js'
import { makeTokenHandler } from './endpoints/token.js'
import { isOAuthAdmin } from './admin/is-admin.js'
import { createRateLimitStore, rateLimitKey } from './middleware/rate-limit.js'
import { wrapMcpEndpointHandler } from './middleware/wrap-mcp.js'
import { isLoopbackUrl } from './lib/loopback.js'
import { OAUTH_AS_METADATA_PATH, OAUTH_PRM_METADATA_PATH } from './lib/paths.js'
import { PayloadMcpOAuthError } from './types.js'

const SUPPORTED_MCP_RANGE = { min: [3, 0, 0], max: [3, 999, 999] } as const

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
}

function withCors(handler: (req: PayloadRequest) => Promise<Response> | Response) {
  return async (req: PayloadRequest): Promise<Response> => {
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS })
    }
    const res = await handler(req as never)
    const headers = new Headers(res.headers)
    headers.set('Access-Control-Allow-Origin', '*')
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers })
  }
}

function resolveConfig(options: PayloadMcpOAuthConfig): ResolvedConfig {
  const { issuer, mcpPluginOptions } = options

  if (!issuer || typeof issuer !== 'string') {
    throw new PayloadMcpOAuthError('MISSING_ISSUER', 'payloadMcpOAuth: issuer is required')
  }
  let issuerUrl: URL
  try {
    issuerUrl = new URL(issuer)
  } catch {
    throw new PayloadMcpOAuthError('INVALID_ISSUER', `payloadMcpOAuth: issuer must be a valid URL, got "${issuer}"`)
  }
  // In production the issuer (and every advertised OAuth endpoint) must be HTTPS:
  // auth codes and bearer tokens travel to/from these URLs.
  //
  // Loopback is exempt. `next build` and `next start` set NODE_ENV=production
  // unconditionally, so this fired on a local production build — a routine
  // pre-deploy check — and there was no way through it short of deploying first
  // or removing the plugin (#71). A loopback issuer is not reachable off the
  // machine, so there is no transport to intercept; this is the same allowance
  // the Dynamic Client Registration redirect_uri validator already made, now
  // sharing one definition with it.
  if (
    process.env['NODE_ENV'] === 'production' &&
    issuerUrl.protocol !== 'https:' &&
    !isLoopbackUrl(issuerUrl)
  ) {
    throw new PayloadMcpOAuthError(
      'INSECURE_ISSUER',
      `payloadMcpOAuth: issuer must use https:// in production, got "${issuer}"`,
    )
  }

  if (!mcpPluginOptions || typeof mcpPluginOptions !== 'object') {
    throw new PayloadMcpOAuthError(
      'MISSING_MCP_OPTIONS',
      'payloadMcpOAuth: mcpPluginOptions is required — pass the same options object you give to mcpPlugin()',
    )
  }

  // Require a real pepper everywhere EXCEPT explicit development/test. The
  // insecure built-in fallback must never be used in production, staging, or any
  // environment that doesn't deliberately set NODE_ENV=development|test — those
  // are the cases where a missing pepper silently used the public DEV_PEPPER.
  const pepper = process.env['PMOAUTH_TOKEN_PEPPER']
  const nodeEnv = process.env['NODE_ENV']
  const isDevOrTest = nodeEnv === 'development' || nodeEnv === 'test'
  if ((!pepper || pepper.length < 32) && !isDevOrTest) {
    // Deliberately NOT exempted for a loopback issuer, unlike the HTTPS check
    // above. The pepper is what makes stored token hashes unforgeable, and the
    // built-in dev fallback ships inside the published package — relaxing it
    // would weaken data at rest, whereas the HTTPS exemption only concerns a
    // transport that does not exist on loopback. A local `next build` reaches
    // here too, so the message names that case rather than assuming a deploy.
    throw new PayloadMcpOAuthError(
      'MISSING_PEPPER',
      'PMOAUTH_TOKEN_PEPPER must be set to a string of at least 32 characters. ' +
        'The insecure built-in fallback is only used when NODE_ENV is "development" or "test", ' +
        'and `next build` / `next start` set NODE_ENV=production even for a local build — ' +
        'so add PMOAUTH_TOKEN_PEPPER to your local .env as well as your deployment. ' +
        'Generate one with: openssl rand -hex 32',
    )
  }

  return {
    issuer: issuer.replace(/\/$/, ''),
    mcpPluginOptions,
    userCollection: options.userCollection ?? 'users',
    adminAccess: resolveAdminAccess(options),
    accessTokenTtlSeconds: options.accessTokenTtlSeconds ?? 3600,
    refreshTokenTtlSeconds: options.refreshTokenTtlSeconds ?? 86400,
    authCodeTtlSeconds: options.authCodeTtlSeconds ?? 300,
    rateLimits: options.rateLimits ?? {},
  }
}

/**
 * Default admin gate when the consumer doesn't supply `adminAccess`: an
 * authenticated user in the configured admin collection. Closes the public
 * REST/GraphQL surface while letting admin-panel operators see/manage the
 * collections. Computed independently of `resolveConfig` so the disabled path
 * (which skips issuer/pepper validation) can still gate the kept collections.
 */
function resolveAdminAccess(options: PayloadMcpOAuthConfig): Access {
  if (options.adminAccess) return options.adminAccess
  const userCollection = options.userCollection ?? 'users'
  // Collection membership ALONE is effectively `Boolean(req.user)` in the common
  // single-`users`-collection app, which would let any logged-in end user rewrite
  // a client's redirectUris (-> auth-code theft) or delete other users' tokens.
  // `isOAuthAdmin` additionally honours a `role`/`isAdmin`/`roles` field when the
  // user collection has one, and returns true when it has none — so the default
  // Payload starters are unaffected while role-bearing apps get the tighter gate.
  //
  // If your operators carry a role OTHER than `admin`, this default will lock
  // them out of the OAuth screens: pass your own `adminAccess` rule instead.
  return ({ req }) => {
    const user = req.user
    if (!user || user.collection !== userCollection) return false
    return isOAuthAdmin(user)
  }
}

/**
 * True when the OAuth layer should be a no-op: the consumer set `disabled`, OR
 * the MCP plugin itself is disabled (we read the shared `mcpPluginOptions` it
 * also reads). In both cases we keep the collections (schema/migration
 * consistency) but add no endpoints, do no token-validation wiring, and never
 * throw PLUGIN_ORDER — `@payloadcms/plugin-mcp` does not register `/mcp` when
 * disabled, so a thrown PLUGIN_ORDER would otherwise crash the app on boot.
 */
export function isPluginDisabled(options: PayloadMcpOAuthConfig): boolean {
  const mcpDisabled = Boolean((options.mcpPluginOptions as { disabled?: boolean } | undefined)?.disabled)
  return options.disabled === true || mcpDisabled
}

/** Open read/update/delete on an operator-facing collection to the admin gate. */
function withAdminAccess(collection: CollectionConfig, adminAccess: Access): CollectionConfig {
  return {
    ...collection,
    access: { ...collection.access, read: adminAccess, update: adminAccess, delete: adminAccess },
  }
}

/**
 * The four collections this plugin manages. `oauth-clients`/`oauth-tokens` are
 * operator-facing (admin-gated under the MCP nav group); auth codes + CSRF
 * nonces stay fully locked + hidden. Registered in every mode (incl. disabled)
 * for schema consistency — they're relationally isolated (text FKs,
 * lockDocuments:false), so keeping them never adds cross-table FK columns.
 */
function oauthCollections(adminAccess: Access): CollectionConfig[] {
  return [
    withAdminAccess(oauthClientsCollection, adminAccess),
    oauthAuthCodesCollection,
    withAdminAccess(oauthTokensCollection, adminAccess),
    oauthCsrfNoncesCollection,
  ]
}

/** The endpoint `@payloadcms/plugin-mcp` registers, by path. */
function isMcpEndpoint(endpoint: Endpoint): boolean {
  return endpoint.path === '/mcp' || endpoint.path === '/api/mcp'
}

function assertMcpPluginRanFirst(config: Config): void {
  if ((config.endpoints ?? []).some(isMcpEndpoint)) return
  throw new PayloadMcpOAuthError(
    'PLUGIN_ORDER',
    'payloadMcpOAuth must be registered AFTER mcpPlugin() in the plugins array. ' +
      'No /mcp endpoint found in incomingConfig — ensure mcpPlugin() runs first.',
  )
}

function warnIfVersionUntested(): void {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require('@payloadcms/plugin-mcp/package.json') as { version?: string }
    const raw = pkg.version ?? ''
    const parts = raw.split('.').map(Number)
    const [major = 0, minor = 0, patch = 0] = parts
    const [minMaj, minMin, minPatch] = SUPPORTED_MCP_RANGE.min
    const [maxMaj, maxMin, maxPatch] = SUPPORTED_MCP_RANGE.max
    const tooOld =
      major < minMaj ||
      (major === minMaj && minor < minMin) ||
      (major === minMaj && minor === minMin && patch < minPatch)
    const tooNew =
      major > maxMaj ||
      (major === maxMaj && minor > maxMin) ||
      (major === maxMaj && minor === maxMin && patch > maxPatch)
    if (tooOld || tooNew) {
      console.warn(
        `[payloadMcpOAuth] @payloadcms/plugin-mcp@${raw} is outside the tested range ` +
          `(${SUPPORTED_MCP_RANGE.min.join('.')}–${SUPPORTED_MCP_RANGE.max.join('.')}). ` +
          `Proceed with caution.`,
      )
    }
  } catch {
    // Package resolution failed — non-fatal
  }
}

export function buildPlugin(incomingConfig: Config, options: PayloadMcpOAuthConfig): Config {
  // Register the collections in every mode — including disabled — so the DB
  // schema stays consistent for migrations (matches the official template +
  // @payloadcms/plugin-mcp). `adminAccess` is resolved here (not via
  // resolveConfig) so the disabled path doesn't require issuer/pepper.
  const collections = [...(incomingConfig.collections ?? []), ...oauthCollections(resolveAdminAccess(options))]

  // No-op path: our `disabled`, or the MCP plugin is disabled. Add no endpoints,
  // wrap nothing, and skip detectMcpEndpoints (a disabled MCP plugin registers no
  // /mcp endpoint, which would otherwise throw PLUGIN_ORDER and crash boot).
  if (isPluginDisabled(options)) {
    return { ...incomingConfig, collections }
  }

  const resolved = resolveConfig(options)
  assertMcpPluginRanFirst(incomingConfig)
  warnIfVersionUntested()

  // T5.4: wrap MCP endpoint handlers to convert OAuthInvalidTokenError → 401
  // and to inject resource_metadata into any 401 responses (RFC 9728).
  // Pass the canonical full pathname (e.g. /api/mcp) so the wrapper can patch
  // req.url after a Next.js middleware rewrite, otherwise the downstream
  // mcp-handler URL match (url.pathname === streamableHttpEndpoint) fails.
  //
  // Derive NEW endpoint objects rather than reassigning `handler` on the ones
  // Payload handed us (#50). The returned config used to share those objects
  // with `incomingConfig`, so building the config mutated its own input —
  // against the "never mutate incoming config" rule in Payload's plugin docs,
  // and not idempotent: wrapping the same object twice would stack wrappers.
  const apiBase = (incomingConfig.routes?.api ?? '/api').replace(/\/$/, '')

  // Both the admin mount point and the login route within it are configurable,
  // and the login redirect has to honour both. This used to pass a hardcoded
  // '/admin', so an app that customised either sent users mid-flow to a URL
  // that does not exist — with no way to override it. `routes.admin` may be '/',
  // which the trailing-slash strip turns into '' so the join stays single-slashed.
  const adminBase = (incomingConfig.routes?.admin ?? '/admin').replace(/\/$/, '')
  const loginRoute = incomingConfig.admin?.routes?.login ?? '/login'
  const loginPath = options.loginPath ?? `${adminBase}${loginRoute}`

  const wrappedEndpoints = (incomingConfig.endpoints ?? []).map((endpoint) => {
    if (!isMcpEndpoint(endpoint) || typeof endpoint.handler !== 'function') return endpoint
    const endpointPath = endpoint.path.startsWith('/api/')
      ? endpoint.path
      : `${apiBase}${endpoint.path.startsWith('/') ? endpoint.path : `/${endpoint.path}`}`
    return {
      ...endpoint,
      handler: wrapMcpEndpointHandler(endpoint.handler, resolved.issuer, endpointPath),
    }
  })

  // T5.5: build rate limiters
  const rateLimits = createRateLimitStore(resolved.rateLimits)

  // Helper to apply rate limiting inside a handler
  function withRateLimit(
    limiter: ReturnType<typeof createRateLimitStore>[keyof ReturnType<typeof createRateLimitStore>],
    handler: (req: PayloadRequest) => Promise<Response> | Response,
  ) {
    return async (req: PayloadRequest): Promise<Response> => {
      const ip = (req.headers.get?.('x-forwarded-for') ?? '').split(',')[0]?.trim()
      const key = rateLimitKey(ip)
      const allowed = limiter.check(key)
      if (!allowed) {
        return Response.json(
          { error: 'too_many_requests', error_description: 'Rate limit exceeded' },
          { status: 429, headers: { 'Cache-Control': 'no-store', 'Retry-After': '60' } },
        )
      }
      return handler(req as never)
    }
  }

  const corsPreflightHandler = () => new Response(null, { status: 204, headers: CORS_HEADERS })

  // T5.5: build OAuth endpoints
  const oauthEndpoints: Endpoint[] = [
    {
      path: OAUTH_AS_METADATA_PATH,
      method: 'get',
      handler: makeAsMetadataHandler(resolved.issuer, apiBase),
    },
    {
      path: OAUTH_PRM_METADATA_PATH,
      method: 'get',
      handler: makePrmMetadataHandler(resolved.issuer),
    },
    {
      path: '/oauth/register',
      method: 'post',
      handler: withCors(withRateLimit(rateLimits.register, makeRegisterHandler())),
    },
    { path: '/oauth/register', method: 'options', handler: corsPreflightHandler },
    {
      path: '/oauth/authorize',
      method: 'get',
      handler: withRateLimit(
        rateLimits.authorize,
        makeAuthorizeHandler({
          loginPath,
          consentPath: `${apiBase}/oauth/consent`,
          authorizePath: `${apiBase}/oauth/authorize`,
          mcpPluginOptions: resolved.mcpPluginOptions,
        }),
      ),
    },
    {
      path: '/oauth/consent',
      method: 'post',
      handler: withRateLimit(
        rateLimits.consent,
        makeConsentHandler(resolved.authCodeTtlSeconds, resolved.issuer, resolved.mcpPluginOptions),
      ),
    },
    {
      path: '/oauth/token',
      method: 'post',
      handler: withCors(
        withRateLimit(
          rateLimits.token,
          makeTokenHandler(resolved.mcpPluginOptions, {
            accessTtlSeconds: resolved.accessTokenTtlSeconds,
            refreshTtlSeconds: resolved.refreshTokenTtlSeconds,
          }),
        ),
      ),
    },
    { path: '/oauth/token', method: 'options', handler: corsPreflightHandler },
    {
      path: '/oauth/revoke',
      method: 'post',
      handler: withCors(withRateLimit(rateLimits.revoke, makeRevokeHandler())),
    },
    { path: '/oauth/revoke', method: 'options', handler: corsPreflightHandler },
  ]

  // T5.5 / T6: merge collections (built above, admin-gated) and OAuth endpoints.
  return {
    ...incomingConfig,
    collections,
    endpoints: [...wrappedEndpoints, ...oauthEndpoints],
  }
}
