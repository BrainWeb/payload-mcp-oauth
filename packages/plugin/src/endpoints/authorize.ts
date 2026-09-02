import type { PayloadHandler } from 'payload'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { makeCsrfToken, storeCsrfNonce } from '../lib/csrf.js'
import { validateCodeChallenge } from '../lib/pkce.js'
import { scopeToCapabilities } from '../lib/scope.js'
import { oauthErrorResponse, redirectResponse } from './helpers.js'

const SCOPE_LABELS: Record<string, string> = {
  'posts:read': 'Read posts',
  'posts:write': 'Create and update posts',
  'posts:delete': 'Delete posts',
  'media:read': 'Read media files',
  'media:write': 'Upload and manage media',
  'users:read': 'Read user profiles',
  openid: 'Confirm your identity',
  profile: 'Access your profile information',
  email: 'Access your email address',
}

function e(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;')
}

function buildConsentHtml(p: {
  clientName: string
  scope: string
  clientId: string
  redirectUri: string
  codeChallenge: string
  codeChallengeMethod: string
  state: string | undefined
  userId: string
  resource: string
  csrfToken: string
  csrfNonce: string
  consentPath: string
  scopeEnforced: boolean
}): string {
  const hasScope = p.scope.trim().length > 0
  const labels = hasScope
    ? p.scope.split(/\s+/).filter(Boolean).map((s) => SCOPE_LABELS[s] ?? s)
    : ['All tools enabled on this server']
  const items = labels.map((l) => `<li>${e(l)}</li>`).join('')
  const note = hasScope && p.scopeEnforced
    ? 'Only the capabilities listed above will be granted, on your behalf. Only approve applications you trust.'
    : 'Approving grants the application access to <strong>all tools enabled on this server</strong>, on your behalf. Only approve applications you trust.'
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize ${e(p.clientName)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 1rem}
h1{font-size:1.25rem;margin-bottom:0.5rem}
.scope-list{list-style:disc;padding-left:1.5rem;margin:1rem 0}
.note{font-size:0.85rem;color:#555;background:#f7f7f7;border-left:3px solid #d0d0d0;padding:0.6rem 0.8rem;margin:1rem 0}
.actions{display:flex;gap:0.75rem;margin-top:1.5rem}
.btn{padding:0.5rem 1.25rem;border:none;border-radius:4px;cursor:pointer;font-size:1rem}
.btn-approve{background:#0070f3;color:#fff}
.btn-deny{background:#f0f0f0;color:#333}
</style>
</head><body>
<h1>Authorize <strong>${e(p.clientName)}</strong></h1>
<p>Approving will let <strong>${e(p.clientName)}</strong> access your Payload CMS instance <strong>acting as you</strong>. It will be granted:</p>
<ul class="scope-list">${items}</ul>
<p class="note">${note}</p>
<form method="POST" action="${e(p.consentPath)}">
<input type="hidden" name="client_id" value="${e(p.clientId)}">
<input type="hidden" name="redirect_uri" value="${e(p.redirectUri)}">
<input type="hidden" name="code_challenge" value="${e(p.codeChallenge)}">
<input type="hidden" name="code_challenge_method" value="${e(p.codeChallengeMethod)}">
<input type="hidden" name="state" value="${e(p.state ?? '')}">
<input type="hidden" name="user_id" value="${e(p.userId)}">
<input type="hidden" name="scope" value="${e(p.scope)}">
<input type="hidden" name="resource" value="${e(p.resource)}">
<input type="hidden" name="csrf_token" value="${e(p.csrfToken)}">
<input type="hidden" name="csrf_nonce" value="${e(p.csrfNonce)}">
<div class="actions">
<button type="submit" name="decision" value="approve" class="btn btn-approve">Approve</button>
<button type="submit" name="decision" value="deny" class="btn btn-deny">Deny</button>
</div>
</form>
</body></html>`
}

function errorRedirect(redirectUri: string | null, error: string, description: string, state?: string): Response {
  if (!redirectUri) {
    return oauthErrorResponse(400, error, description)
  }
  const url = new URL(redirectUri)
  url.searchParams.set('error', error)
  url.searchParams.set('error_description', description)
  if (state) url.searchParams.set('state', state)
  return redirectResponse(url.toString())
}

export interface AuthorizeHandlerOptions {
  /**
   * Where to send an unauthenticated user to sign in, as an app-absolute path.
   * Built by the caller from `routes.admin` + `admin.routes.login`, both of
   * which an app may customise.
   * @default '/admin/login'
   */
  loginPath?: string
  /** Where the consent form POSTs. @default '/api/oauth/consent' */
  consentPath?: string
  /**
   * This endpoint's own path, used to rebuild the post-login return URL when
   * `req.url` cannot be parsed. @default '/api/oauth/authorize'
   */
  authorizePath?: string
  /** Enables scope validation and the narrowed-grant consent copy. */
  mcpPluginOptions?: MCPPluginConfig
}

/**
 * Named options rather than positional arguments on purpose: the previous
 * signature led the caller to pass `('/admin', undefined, ...)`, which reads as
 * a deliberate choice but silently ignored an app's configured admin route.
 */
export function makeAuthorizeHandler(options: AuthorizeHandlerOptions = {}): PayloadHandler {
  const {
    loginPath = '/admin/login',
    consentPath = '/api/oauth/consent',
    authorizePath = '/api/oauth/authorize',
    mcpPluginOptions,
  } = options

  return async (req) => {
    const q = req.query as Record<string, string | undefined>
    const responseType = q['response_type']
    const clientId = q['client_id']
    const redirectUri = q['redirect_uri']
    const codeChallenge = q['code_challenge']
    const codeChallengeMethod = q['code_challenge_method']
    const state = q['state']
    const scope = q['scope'] ?? ''
    const resource = q['resource'] ?? ''

    if (responseType !== 'code') {
      return errorRedirect(null, 'unsupported_response_type', 'Only response_type=code is supported', state)
    }

    if (!clientId || typeof clientId !== 'string') {
      return errorRedirect(null, 'invalid_request', 'client_id is required', state)
    }

    const { docs } = await req.payload.find({
      collection: 'oauth-clients',
      overrideAccess: true,
      where: { clientId: { equals: clientId }, isActive: { equals: true } },
      limit: 1,
    })
    const client = docs[0]

    if (!client) {
      return errorRedirect(null, 'invalid_client', 'Unknown client_id', state)
    }

    const registered = (client['redirectUris'] as Array<{ uri: string }>).map((r) => r.uri)
    if (!redirectUri || !registered.includes(redirectUri)) {
      return errorRedirect(null, 'invalid_redirect_uri', 'redirect_uri does not match registered URIs', state)
    }

    if (!codeChallenge || typeof codeChallenge !== 'string') {
      return errorRedirect(redirectUri, 'invalid_request', 'code_challenge is required', state)
    }

    if (codeChallengeMethod !== 'S256') {
      return errorRedirect(redirectUri, 'invalid_request', 'code_challenge_method must be S256', state)
    }

    if (!validateCodeChallenge(codeChallenge)) {
      return errorRedirect(redirectUri, 'invalid_request', 'code_challenge must be 43 base64url characters (RFC 7636 S256)', state)
    }

    // Validate scope against operator-enabled capabilities (RFC 6749 §4.1.2.1)
    if (scope && mcpPluginOptions) {
      const scopeResult = scopeToCapabilities(scope, mcpPluginOptions)
      if (scopeResult.kind === 'invalid') {
        return errorRedirect(redirectUri, 'invalid_scope', `Unknown or unsupported scope: ${scopeResult.invalidScopes.join(' ')}`, state)
      }
    }

    // state is RECOMMENDED but optional per OAuth 2.1 — do not reject absent state
    const user = req.user
    if (!user) {
      // Use path+search only — avoids localhost vs tunnel protocol mismatch
      let returnPath = authorizePath
      try {
        const u = new URL(req.url ?? '')
        returnPath = u.pathname + u.search
      } catch {
        // req.url was a relative path already
        returnPath = req.url ?? authorizePath
      }
      return redirectResponse(`${loginPath}?redirect=${encodeURIComponent(returnPath)}`)
    }

    const clientName = String(client['clientName'] ?? clientId)
    const userId = String((user as Record<string, unknown>)['id'] ?? '')
    const csrfToken = makeCsrfToken(userId, clientId, redirectUri, codeChallenge)
    const csrfNonce = await storeCsrfNonce(req.payload, userId)

    return new Response(buildConsentHtml({ clientName, scope, clientId, redirectUri, codeChallenge, codeChallengeMethod, state, userId, resource, csrfToken, csrfNonce, consentPath, scopeEnforced: !!mcpPluginOptions }), {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        // MUST NOT be 'no-referrer': per the Fetch spec, a 'no-referrer' page sends
        // `Origin: null` on its form submissions, and Payload rejects cookie auth on
        // a null-origin POST — so the Approve submit loses req.user and the consent
        // endpoint 401s. 'strict-origin-when-cross-origin' (the documented value in
        // the threat model, row I6) keeps the real Origin on this same-origin POST
        // while still stripping the full URL from the cross-origin client callback.
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        // form-action omitted intentionally: Chrome blocks form-POST redirects to
        // origins not in form-action, and the consent redirect goes to the client's
        // localhost callback (random port). default-src 'none' already blocks XSS,
        // so form-action adds no practical security here.
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
      },
    })
  }
}
