import type { PayloadHandler } from 'payload'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { verifyCsrfToken, consumeCsrfNonce } from '../lib/csrf.js'
import { issueAuthCode } from '../lib/auth-codes.js'
import { scopeToCapabilities } from '../lib/scope.js'
import { readRegisteredUris } from './authorize.js'
import { oauthErrorResponse, redirectResponse, parseBody } from './helpers.js'

export function makeConsentHandler(authCodeTtlSeconds = 300, issuer = '', mcpPluginOptions?: MCPPluginConfig): PayloadHandler {
  return async (req) => {
    try {
      if (req.method !== 'POST') {
        return oauthErrorResponse(405, 'invalid_request', 'Method not allowed')
      }

      // Session binding: auth codes are minted here, so the logged-in session
      // gate enforced at /authorize MUST be re-enforced. Never trust the user
      // identity from the request body — derive it from the authenticated
      // session and bind the code (and CSRF check) to that user.
      const sessionUserId = String((req.user as Record<string, unknown> | null | undefined)?.['id'] ?? '')
      if (!sessionUserId) {
        return oauthErrorResponse(401, 'access_denied', 'Authentication required')
      }

      const body = await parseBody(req)

      const decision = body['decision'] as string | undefined
      const clientId = body['client_id'] as string | undefined
      const redirectUri = body['redirect_uri'] as string | undefined
      const codeChallenge = body['code_challenge'] as string | undefined
      const codeChallengeMethod = body['code_challenge_method'] as string | undefined
      const state = body['state'] as string | undefined
      // Coerce to string: Payload IDs are often integers, so a JSON client may
      // send user_id as a number. Without this, the strict !== check below would
      // spuriously 403 a legitimate request (123 !== "123").
      const bodyUserId = body['user_id'] != null ? String(body['user_id']) : undefined
      const csrfToken = body['csrf_token'] as string | undefined
      const csrfNonce = body['csrf_nonce'] as string | undefined
      const scope = (body['scope'] as string | undefined) ?? ''
      const resource = (body['resource'] as string | undefined) ?? ''

      if (!clientId || !redirectUri || !codeChallenge || !codeChallengeMethod || !csrfToken || !csrfNonce) {
        return oauthErrorResponse(400, 'invalid_request', 'Missing required consent parameters')
      }

      // Defense in depth: if the form carried a user_id, it must match the
      // session. The authoritative identity is always the session user.
      if (bodyUserId && bodyUserId !== sessionUserId) {
        return oauthErrorResponse(403, 'access_denied', 'Session does not match the authorization request')
      }

      // CSRF token is verified against the *session* user — a token minted for a
      // different user (or a replay past its TTL) will not validate.
      if (!verifyCsrfToken(csrfToken, sessionUserId, clientId, redirectUri, codeChallenge)) {
        return oauthErrorResponse(400, 'invalid_request', 'Invalid or expired CSRF token')
      }

      // Single-use nonce: atomically marks the nonce consumed so the same consent
      // form cannot be submitted twice (prevents duplicate auth code issuance).
      if (!(await consumeCsrfNonce(req.payload, csrfNonce, sessionUserId))) {
        return oauthErrorResponse(400, 'invalid_request', 'CSRF nonce already used or expired')
      }

      // Re-validate scope at consent time to prevent tampering with the hidden scope field
      if (scope && mcpPluginOptions) {
        const scopeResult = scopeToCapabilities(scope, mcpPluginOptions)
        if (scopeResult.kind === 'invalid') {
          return oauthErrorResponse(400, 'invalid_scope', `Unknown or unsupported scope: ${scopeResult.invalidScopes.join(' ')}`)
        }
      }

      if (decision === 'deny') {
        const url = new URL(redirectUri)
        url.searchParams.set('error', 'access_denied')
        url.searchParams.set('error_description', 'The user denied the authorization request')
        if (state) url.searchParams.set('state', state)
        // RFC 9207 §2 requires `iss` on ALL authorization responses, errors
        // included. Without it a client that honours our advertised
        // `authorization_response_iss_parameter_supported` must reject the
        // response (§2.4) — turning "the user pressed Deny" into a protocol
        // violation instead of a clean access_denied.
        if (issuer) url.searchParams.set('iss', issuer)
        return redirectResponse(url.toString())
      }

      if (decision !== 'approve') {
        return oauthErrorResponse(400, 'invalid_request', 'decision must be approve or deny')
      }

      const { docs } = await req.payload.find({
        collection: 'oauth-clients',
        overrideAccess: true,
        where: { clientId: { equals: clientId }, isActive: { equals: true } },
        limit: 1,
      })
      const client = docs[0]
      if (!client) {
        return oauthErrorResponse(400, 'invalid_client', 'Unknown client_id')
      }
      const registered = readRegisteredUris(client)
      if (!registered.includes(redirectUri)) {
        return oauthErrorResponse(400, 'invalid_redirect_uri', 'redirect_uri does not match registered URIs')
      }

      if (codeChallengeMethod !== 'S256') {
        return oauthErrorResponse(400, 'invalid_request', 'code_challenge_method must be S256')
      }

      const code = await issueAuthCode(req.payload, {
        clientId,
        userId: sessionUserId,
        redirectUri,
        scope,
        codeChallenge,
        codeChallengeMethod,
        ttlSeconds: authCodeTtlSeconds,
      })

      const url = new URL(redirectUri)
      url.searchParams.set('code', code)
      if (state) url.searchParams.set('state', state)
      // RFC 9207: include iss so clients can verify the authorization server identity
      if (issuer) url.searchParams.set('iss', issuer)
      // RFC 8707: echo resource back to the client unchanged
      if (resource) url.searchParams.set('resource', resource)
      return redirectResponse(url.toString())
    } catch (err) {
      console.error('[pmoauth] consent endpoint error:', err)
      return oauthErrorResponse(500, 'server_error', 'An internal server error occurred')
    }
  }
}
