import { describe, expect, it, vi } from 'vitest'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { makeAuthorizeHandler, readRegisteredUris } from '../../../src/endpoints/authorize.js'
import { verifyCsrfToken } from '../../../src/lib/csrf.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const MCP_OPTIONS: MCPPluginConfig = {
  collections: { posts: { enabled: true } },
}

const REGISTERED_URI = 'https://example.com/cb'
const VALID_CLIENT = {
  id: 'client-doc-1',
  clientId: 'client-1',
  clientName: 'Test App',
  redirectUris: [{ uri: REGISTERED_URI }],
  isActive: true,
}

function makeReq(query: Record<string, string | undefined>, user: unknown = null) {
  return {
    method: 'GET',
    query,
    user,
    url: '/api/oauth/authorize',
    headers: new Headers(),
    payload: {
      find: vi.fn().mockResolvedValue({ docs: [VALID_CLIENT] }),
      create: vi.fn().mockResolvedValue({ id: 'nonce-doc-1' }),
    },
  }
}

const VALID_QUERY = {
  response_type: 'code',
  client_id: 'client-1',
  redirect_uri: REGISTERED_URI,
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
  state: 'random-state-value',
}

describe('makeAuthorizeHandler', () => {
  it('sends an unauthenticated user to a custom login path', async () => {
    const res = await makeAuthorizeHandler({ loginPath: '/staff/sign-in' })(
      makeReq(VALID_QUERY, null) as never,
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/staff/sign-in?redirect=')
  })

  it('returns the user to the authorize endpoint after login, preserving the query', async () => {
    const req = makeReq(VALID_QUERY, null)
    req.url = 'https://cms.example.com/api/oauth/authorize?response_type=code&client_id=client-1'
    const res = await makeAuthorizeHandler()(req as never)
    const location = res.headers.get('Location') ?? ''
    const redirect = decodeURIComponent(location.split('redirect=')[1] ?? '')
    // Path + search only — an absolute URL would break behind a tunnel whose
    // public origin differs from the one Payload sees.
    expect(redirect).toBe('/api/oauth/authorize?response_type=code&client_id=client-1')
  })

  it('falls back to the configured authorize path when req.url is unparseable', async () => {
    const req = makeReq(VALID_QUERY, null)
    req.url = undefined
    const res = await makeAuthorizeHandler({ authorizePath: '/cms/oauth/authorize' })(req as never)
    const location = res.headers.get('Location') ?? ''
    expect(decodeURIComponent(location)).toContain('/cms/oauth/authorize')
  })

  it('redirects unauthenticated users to login', async () => {
    const res = await makeAuthorizeHandler()(makeReq(VALID_QUERY, null) as never)
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/admin/login')
  })

  it('renders consent HTML for authenticated users', async () => {
    const res = await makeAuthorizeHandler()(makeReq(VALID_QUERY, { id: 'user-1' }) as never)
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Test App')
    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
  })

  it('discloses full-grant when scope is absent (all tools enabled on this server)', async () => {
    // No scope → full operator grant; the note must reflect this.
    const res = await makeAuthorizeHandler()(makeReq(VALID_QUERY, { id: 'user-1' }) as never)
    const html = await res.text()
    expect(html).toMatch(/acting as you/i)
    expect(html).toMatch(/all tools enabled on this server/i)
  })

  it('rejects unsupported response_type with JSON error', async () => {
    const res = await makeAuthorizeHandler()(makeReq({ ...VALID_QUERY, response_type: 'token' }) as never)
    const body = await res.json() as Record<string, unknown>
    expect(body['error']).toBe('unsupported_response_type')
  })

  it('rejects missing client_id with JSON error', async () => {
    const req = makeReq({ ...VALID_QUERY, client_id: undefined })
    req.payload.find = vi.fn().mockResolvedValue({ docs: [] })
    const res = await makeAuthorizeHandler()(req as never)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_request')
  })

  it('rejects unknown client_id with JSON error', async () => {
    const req = makeReq({ ...VALID_QUERY, client_id: 'unknown' })
    req.payload.find = vi.fn().mockResolvedValue({ docs: [] })
    const res = await makeAuthorizeHandler()(req as never)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_client')
  })

  it('rejects open-redirect attempt — no Location header to attacker', async () => {
    const res = await makeAuthorizeHandler()(
      makeReq({ ...VALID_QUERY, redirect_uri: 'https://attacker.example.com/steal' }) as never,
    )
    const body = await res.json() as Record<string, unknown>
    expect(body['error']).toBe('invalid_redirect_uri')
    expect(res.headers.get('Location')).toBeNull()
  })

  it('redirects error to redirect_uri when missing code_challenge', async () => {
    const res = await makeAuthorizeHandler()(
      makeReq({ ...VALID_QUERY, code_challenge: undefined }, { id: 'u1' }) as never,
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('error=invalid_request')
  })

  it('rejects plain code_challenge_method', async () => {
    const res = await makeAuthorizeHandler()(
      makeReq({ ...VALID_QUERY, code_challenge_method: 'plain' }, { id: 'u1' }) as never,
    )
    expect(res.headers.get('Location')).toContain('error=invalid_request')
  })

  it('rejects a code_challenge that does not conform to RFC 7636 (wrong length)', async () => {
    const res = await makeAuthorizeHandler()(
      makeReq({ ...VALID_QUERY, code_challenge: 'tooshort' }, { id: 'u1' }) as never,
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('error=invalid_request')
  })

  it('renders consent HTML when state is absent (state is optional per OAuth 2.1)', async () => {
    const res = await makeAuthorizeHandler()(
      makeReq({ ...VALID_QUERY, state: undefined }, { id: 'u1' }) as never,
    )
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Test App')
  })

  it('sets security headers on consent HTML', async () => {
    const res = await makeAuthorizeHandler()(makeReq(VALID_QUERY, { id: 'user-1' }) as never)
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy()
    // MUST NOT be 'no-referrer': that makes the browser send `Origin: null` on the
    // Approve form POST, which Payload rejects for cookie auth → consent 401s.
    // strict-origin-when-cross-origin keeps the real Origin on the same-origin POST.
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
    expect(res.headers.get('Referrer-Policy')).not.toBe('no-referrer')
  })

  it('embeds a server-signed CSRF token bound to user/client/redirect/challenge', async () => {
    const res = await makeAuthorizeHandler()(makeReq(VALID_QUERY, { id: 'user-1' }) as never)
    const html = await res.text()
    const m = html.match(/name="csrf_token" value="([^"]+)"/)
    expect(m).not.toBeNull()
    const token = m![1] as string
    // The embedded token is time-bound and must validate for the bound params...
    expect(verifyCsrfToken(token, 'user-1', VALID_QUERY.client_id, REGISTERED_URI, VALID_QUERY.code_challenge)).toBe(true)
    // ...but not for a different user (no cross-user consent).
    expect(verifyCsrfToken(token, 'other-user', VALID_QUERY.client_id, REGISTERED_URI, VALID_QUERY.code_challenge)).toBe(false)
  })

  it('embeds a single-use csrf_nonce in the consent form', async () => {
    const req = makeReq(VALID_QUERY, { id: 'user-1' })
    const res = await makeAuthorizeHandler()(req as never)
    const html = await res.text()
    expect(html).toContain('name="csrf_nonce"')
    expect(req.payload.create).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'oauth-csrf-nonces', overrideAccess: true }),
    )
  })

  it('uses the configured consentPath as the form action', async () => {
    const res = await makeAuthorizeHandler({ consentPath: '/cms/oauth/consent' })(
      makeReq(VALID_QUERY, { id: 'user-1' }) as never,
    )
    const html = await res.text()
    expect(html).toContain('action="/cms/oauth/consent"')
    expect(html).not.toContain('action="/api/oauth/consent"')
  })

  it('redirects with invalid_scope for an unknown scope token (scope enforcement active)', async () => {
    const res = await makeAuthorizeHandler({ mcpPluginOptions: MCP_OPTIONS })(
      makeReq({ ...VALID_QUERY, scope: 'unknown:read' }, { id: 'user-1' }) as never,
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('error=invalid_scope')
  })

  it('accepts a valid scope token and shows the per-scope note when enforcement is active', async () => {
    const res = await makeAuthorizeHandler({ mcpPluginOptions: MCP_OPTIONS })(
      makeReq({ ...VALID_QUERY, scope: 'posts:read' }, { id: 'user-1' }) as never,
    )
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Read posts')
    expect(html).toContain('Only the capabilities listed above will be granted')
  })

  it('accepts empty scope without scope validation and shows the full-grant note', async () => {
    const res = await makeAuthorizeHandler({ mcpPluginOptions: MCP_OPTIONS })(
      makeReq({ ...VALID_QUERY, scope: undefined }, { id: 'user-1' }) as never,
    )
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toMatch(/all tools enabled on this server/i)
  })
})

describe('readRegisteredUris', () => {
  it('reads the uri from each entry', () => {
    expect(readRegisteredUris({ redirectUris: [{ uri: 'https://a/cb' }, { uri: 'https://b/cb' }] })).toEqual([
      'https://a/cb',
      'https://b/cb',
    ])
  })

  it('returns nothing for a missing or non-array value, rather than throwing', () => {
    // The value comes back from the database. A bare cast turned a malformed row
    // into a TypeError — a 500 where the caller should see invalid_redirect_uri.
    expect(readRegisteredUris({})).toEqual([])
    expect(readRegisteredUris({ redirectUris: null })).toEqual([])
    expect(readRegisteredUris({ redirectUris: 'https://a/cb' })).toEqual([])
  })

  it('skips malformed entries instead of failing the whole list', () => {
    expect(
      readRegisteredUris({ redirectUris: [{ uri: 'https://a/cb' }, null, {}, { uri: 42 }] }),
    ).toEqual(['https://a/cb'])
  })
})

describe('makeAuthorizeHandler — malformed client row', () => {
  it('rejects with invalid_redirect_uri rather than a 500', async () => {
    const req = makeReq(VALID_QUERY, { id: 'user-1' })
    req.payload.find = vi.fn().mockResolvedValue({
      docs: [{ ...VALID_CLIENT, redirectUris: null }],
    })
    const res = await makeAuthorizeHandler()(req as never)
    // Fails closed: no registered URI matches, so nothing is redirected anywhere.
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_redirect_uri')
  })
})

describe('makeAuthorizeHandler — RFC 9207 iss on error responses', () => {
  const ISSUER = 'https://cms.example.com'

  it('includes iss on an invalid_scope error redirect', async () => {
    // RFC 9207 §2 requires iss on ALL authorization responses, errors included.
    // We advertise authorization_response_iss_parameter_supported, so §2.4 says
    // a client MUST reject a response without it — omitting it here would turn
    // an ordinary invalid_scope into a protocol violation at the client.
    const res = await makeAuthorizeHandler({ mcpPluginOptions: MCP_OPTIONS, issuer: ISSUER })(
      makeReq({ ...VALID_QUERY, scope: 'unknown:read' }, { id: 'user-1' }) as never,
    )
    const url = new URL(res.headers.get('Location') ?? '')
    expect(url.searchParams.get('error')).toBe('invalid_scope')
    expect(url.searchParams.get('iss')).toBe(ISSUER)
  })

  it('includes iss on a bad code_challenge error redirect', async () => {
    const res = await makeAuthorizeHandler({ issuer: ISSUER })(
      makeReq({ ...VALID_QUERY, code_challenge: 'too-short' }, { id: 'user-1' }) as never,
    )
    const url = new URL(res.headers.get('Location') ?? '')
    expect(url.searchParams.get('error')).toBe('invalid_request')
    expect(url.searchParams.get('iss')).toBe(ISSUER)
  })

  it('preserves state alongside iss', async () => {
    const res = await makeAuthorizeHandler({ issuer: ISSUER })(
      makeReq({ ...VALID_QUERY, code_challenge_method: 'plain' }, { id: 'user-1' }) as never,
    )
    const url = new URL(res.headers.get('Location') ?? '')
    expect(url.searchParams.get('state')).toBe(VALID_QUERY.state)
    expect(url.searchParams.get('iss')).toBe(ISSUER)
  })

  it('omits iss when no issuer is configured, rather than emitting an empty one', () => {
    // Direct construction without an issuer must not produce `iss=`.
    return makeAuthorizeHandler({})(
      makeReq({ ...VALID_QUERY, code_challenge: 'bad' }, { id: 'user-1' }) as never,
    ).then((res) => {
      const url = new URL(res.headers.get('Location') ?? '')
      expect(url.searchParams.has('iss')).toBe(false)
    })
  })
})
