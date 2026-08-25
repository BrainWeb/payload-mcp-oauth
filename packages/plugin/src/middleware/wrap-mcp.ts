import type { MCPAccessSettings, MCPPluginConfig } from '@payloadcms/plugin-mcp'
import type { PayloadRequest, TypedUser } from 'payload'
import { UnauthorizedError } from 'payload'
import { validateAccessToken } from '../lib/validate.js'
import { buildFullCapabilities } from '../lib/scope.js'
import { OAUTH_PRM_METADATA_PATH } from '../lib/paths.js'
import { OAuthInvalidTokenError } from '../types.js'

/**
 * Installs an `overrideAuth` function on the shared MCP plugin options reference.
 * When the Bearer token starts with `pmoauth_`, the OAuth validation path runs;
 * otherwise, the original API-key path is preserved.
 *
 * The handler wrapper (wrapMcpEndpointHandler) must be applied to the MCP endpoint
 * so that OAuthInvalidTokenError thrown here is converted to a 401 Response.
 */
export function installOverrideAuth(mcpPluginOptions: MCPPluginConfig, userCollection: string): void {
  mcpPluginOptions.overrideAuth = async (req, getDefaultMcpAccessSettings) => {
    const bearer = req.headers.get?.('Authorization')?.replace(/^Bearer\s+/i, '')

    if (!bearer?.startsWith('pmoauth_')) {
      return getDefaultMcpAccessSettings()
    }

    // Log the KIND prefix only (`pmoauth_at_` is 11 chars). Slicing to 18 leaked
    // 7 characters of the 43-char secret into logs on every request, which
    // contradicts threat-model row I1 ("never log ... token values").
    req.payload.logger?.info(`[pmoauth] overrideAuth: validating token prefix=${bearer.slice(0, 11)}`)

    const ctx = await validateAccessToken(req.payload, bearer)
    if (!ctx) {
      req.payload.logger?.warn('[pmoauth] overrideAuth: validateAccessToken returned null — token not found/expired/revoked')
      throw new OAuthInvalidTokenError()
    }

    req.payload.logger?.info(`[pmoauth] overrideAuth: token valid, userId=${ctx.userId}, fetching user`)

    let user
    try {
      user = await req.payload.findByID({
        collection: userCollection,
        overrideAccess: true,
        id: ctx.userId,
      })
    } catch (err) {
      req.payload.logger?.error(`[pmoauth] overrideAuth: findByID failed for userId=${ctx.userId}: ${String(err)}`)
      throw new OAuthInvalidTokenError()
    }

    if (!user) {
      req.payload.logger?.warn(`[pmoauth] overrideAuth: user not found for userId=${ctx.userId}`)
      throw new OAuthInvalidTokenError()
    }

    // Set collection/strategy metadata so Payload's access-control layer recognises the user,
    // matching what the API key flow sets before returning from getDefaultMcpAccessSettings.
    const typedUser = user as TypedUser & Record<string, unknown>
    typedUser['collection'] = userCollection
    typedUser['_strategy'] = 'local-jwt'

    req.payload.logger?.info(`[pmoauth] overrideAuth: success, returning MCPAccessSettings`)

    // Use stored token capabilities if explicitly set; otherwise derive from plugin config.
    // Tokens issued by this plugin in v1 always store {} — the plugin config is authoritative.
    const capabilities =
      Object.keys(ctx.capabilities).length > 0 ? ctx.capabilities : buildFullCapabilities(mcpPluginOptions)

    return {
      ...capabilities,
      user: typedUser as TypedUser,
    } as MCPAccessSettings
  }
}

/**
 * Wraps a PayloadHandler so that:
 * - OAuthInvalidTokenError thrown by overrideAuth is converted to a spec-compliant 401
 * - Any 401 from the underlying MCP handler gets resource_metadata appended to
 *   WWW-Authenticate per RFC 9728, enabling client AS discovery
 */
export function wrapMcpEndpointHandler(
  original: (req: PayloadRequest) => Promise<Response> | Response,
  issuer: string,
  canonicalPathname?: string,
): (req: PayloadRequest) => Promise<Response> {
  const prmUrl = `${issuer.replace(/\/$/, '')}${OAUTH_PRM_METADATA_PATH}`

  function addResourceMetadata(wwwAuth: string | null): string {
    const resourceMeta = `resource_metadata="${prmUrl}"`
    if (!wwwAuth) return `Bearer ${resourceMeta}`
    if (wwwAuth.includes('resource_metadata=')) return wwwAuth
    return `${wwwAuth}, ${resourceMeta}`
  }

  return async (req) => {
    // After a Next.js middleware rewrite (e.g. POST / → /api/mcp), Payload's
    // routing matches but req.url still has the original pathname. The MCP
    // handler downstream does `url.pathname === '/api/mcp'` and returns 404
    // if it doesn't match. Wrap req in a Proxy that overrides `url` so the
    // rewritten request behaves identically to a direct hit on the endpoint.
    let effectiveReq = req
    if (canonicalPathname && req.url) {
      try {
        const u = new URL(req.url)
        if (u.pathname !== canonicalPathname) {
          u.pathname = canonicalPathname
          const patchedUrl = u.toString()
          effectiveReq = new Proxy(req, {
            get(target, prop, receiver) {
              if (prop === 'url') return patchedUrl
              return Reflect.get(target, prop, receiver)
            },
          })
        }
      } catch {
        // req.url not absolute — leave as-is
      }
    }
    try {
      const res = await original(effectiveReq)
      if (res.status === 401) {
        const headers = new Headers(res.headers)
        headers.set('WWW-Authenticate', addResourceMetadata(res.headers.get('WWW-Authenticate')))
        return new Response(res.body, { status: 401, statusText: res.statusText, headers })
      }
      return res
    } catch (err) {
      if (err instanceof OAuthInvalidTokenError) {
        return new Response(null, {
          status: 401,
          headers: {
            'WWW-Authenticate': `Bearer error="invalid_token", error_description="OAuth token is invalid or expired", resource_metadata="${prmUrl}"`,
            'Cache-Control': 'no-store',
          },
        })
      }
      // Payload's MCP handler throws UnauthorizedError when there is no Bearer token or the
      // API-key path finds nothing. Catch it here so we can return a proper OAuth challenge
      // with resource_metadata, enabling the client to discover the authorization server.
      if (err instanceof UnauthorizedError) {
        return new Response(null, {
          status: 401,
          headers: {
            'WWW-Authenticate': `Bearer resource_metadata="${prmUrl}"`,
            'Cache-Control': 'no-store',
          },
        })
      }
      throw err
    }
  }
}
