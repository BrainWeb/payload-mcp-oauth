import type { PayloadHandler, PayloadRequest } from 'payload'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { consumeAuthCode } from '../lib/auth-codes.js'
import { validateCodeVerifier } from '../lib/pkce.js'
import { issueTokenPair, rotateRefreshToken } from '../lib/tokens.js'
import { scopeToCapabilities } from '../lib/scope.js'
import { oauthErrorResponse, jsonResponse, parseBody } from './helpers.js'

/**
 * Lifetimes applied to every token this endpoint mints. Threaded from the
 * resolved plugin config so an operator who shortens `accessTokenTtlSeconds`
 * actually gets shorter-lived credentials — previously these were resolved in
 * plugin.ts and then dropped on the floor, so `lib/tokens.ts`'s own defaults
 * always won and the setting was silently inert.
 */
export interface TokenTtls {
  accessTtlSeconds: number
  refreshTtlSeconds: number
}

export function makeTokenHandler(mcpPluginOptions?: MCPPluginConfig, ttls?: TokenTtls): PayloadHandler {
  return async (req) => {
    try {
      if (req.method !== 'POST') {
        return oauthErrorResponse(405, 'invalid_request', 'Method not allowed')
      }

      const body = await parseBody(req)
      const grantType = body['grant_type'] as string | undefined

      if (!grantType) {
        return oauthErrorResponse(400, 'invalid_request', 'grant_type is required')
      }

      if (grantType === 'authorization_code') {
        return await handleAuthCode(req, body, mcpPluginOptions, ttls)
      }

      if (grantType === 'refresh_token') {
        return await handleRefresh(req, body, ttls)
      }

      return oauthErrorResponse(400, 'unsupported_grant_type', `Unsupported grant_type: ${grantType}`)
    } catch (err) {
      console.error('[pmoauth] token endpoint error:', err)
      return oauthErrorResponse(500, 'server_error', 'An internal server error occurred')
    }
  }
}

async function handleAuthCode(
  req: PayloadRequest,
  body: Record<string, unknown>,
  mcpPluginOptions?: MCPPluginConfig,
  ttls?: TokenTtls,
): Promise<Response> {
  const code = body['code'] as string | undefined
  const clientId = body['client_id'] as string | undefined
  const redirectUri = body['redirect_uri'] as string | undefined
  const codeVerifier = body['code_verifier'] as string | undefined

  if (!code || !clientId || !redirectUri || !codeVerifier) {
    return oauthErrorResponse(400, 'invalid_request', 'code, client_id, redirect_uri, and code_verifier are required')
  }

  if (!validateCodeVerifier(codeVerifier)) {
    return oauthErrorResponse(400, 'invalid_request', 'code_verifier does not conform to RFC 7636 (43-128 unreserved chars)')
  }

  const ctx = await consumeAuthCode(req.payload, code, { clientId, redirectUri, codeVerifier })
  if (!ctx) {
    return oauthErrorResponse(400, 'invalid_grant', 'Authorization code is invalid, expired, or already used')
  }

  // Resolve the granted capabilities from the requested scope. The `valid` flag
  // MUST be honoured: scopeToCapabilities returns capabilities:{} for BOTH an
  // empty scope (intentional full grant, applied by the wrap-mcp fallback) AND
  // an invalid scope (grant nothing). Storing {} for the invalid case would let
  // wrap-mcp widen it back to FULL capabilities — a privilege escalation that
  // defeats narrowing (e.g. the operator disabled a collection after the auth
  // code was issued). So an invalid scope is rejected here, never issued.
  let capabilities: Record<string, unknown> = {}
  if (mcpPluginOptions) {
    const scopeResult = scopeToCapabilities(ctx.scope ?? '', mcpPluginOptions)
    if (!scopeResult.valid) {
      return oauthErrorResponse(
        400,
        'invalid_scope',
        `Requested scope can no longer be granted: ${scopeResult.invalidScopes.join(' ')}`,
      )
    }
    capabilities = scopeResult.capabilities
  }

  const pair = await issueTokenPair(req.payload, {
    clientId: ctx.clientId,
    userId: ctx.userId,
    scope: ctx.scope,
    capabilities,
    accessTtlSeconds: ttls?.accessTtlSeconds,
    refreshTtlSeconds: ttls?.refreshTtlSeconds,
  })

  return jsonResponse(pair)
}

async function handleRefresh(
  req: PayloadRequest,
  body: Record<string, unknown>,
  ttls?: TokenTtls,
): Promise<Response> {
  const refreshToken = body['refresh_token'] as string | undefined
  const clientId = body['client_id'] as string | undefined

  if (!refreshToken || !clientId) {
    return oauthErrorResponse(400, 'invalid_request', 'refresh_token and client_id are required')
  }

  const pair = await rotateRefreshToken(req.payload, refreshToken, {
    clientId,
    accessTtlSeconds: ttls?.accessTtlSeconds,
    refreshTtlSeconds: ttls?.refreshTtlSeconds,
  })
  if (!pair) {
    return oauthErrorResponse(400, 'invalid_grant', 'Refresh token is invalid, expired, or revoked')
  }

  return jsonResponse(pair)
}
