import { describe, expect, it, vi } from 'vitest'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { makeConsentHandler } from '../../../src/endpoints/consent.js'
import { makeCsrfToken } from '../../../src/lib/csrf.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const MCP_OPTIONS: MCPPluginConfig = {
  collections: { posts: { enabled: true } },
}

const REGISTERED_URI = 'https://example.com/cb'
const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

const VALID_CLIENT = {
  id: 'client-doc-1',
  clientId: 'client-1',
  redirectUris: [{ uri: REGISTERED_URI }],
  isActive: true,
}

const VALID_BODY = {
  decision: 'approve',
  client_id: 'client-1',
  redirect_uri: REGISTERED_URI,
  code_challenge: CODE_CHALLENGE,
  code_challenge_method: 'S256',
  state: 'csrf-state',
  user_id: 'user-1',
  scope: 'posts:read',
  csrf_token: makeCsrfToken('user-1', 'client-1', REGISTERED_URI, CODE_CHALLENGE),
  csrf_nonce: 'aabbccddeeff00112233445566778899',
}

function makeReq(body: unknown, method = 'POST', user: unknown = { id: 'user-1' }) {
  return {
    method,
    user,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn(),
    payload: {
      find: vi.fn().mockResolvedValue({ docs: [VALID_CLIENT] }),
      create: vi.fn().mockResolvedValue({ id: 'code-doc-1' }),
      update: vi.fn().mockResolvedValue({ docs: [{ id: 'nonce-doc-1' }] }),
    },
  }
}

describe('makeConsentHandler', () => {
  it('redirects with code on approval', async () => {
    const res = await makeConsentHandler()(makeReq(VALID_BODY) as never)
    expect(res.status).toBe(302)
    const location = res.headers.get('Location') ?? ''
    expect(location).toContain('code=pmoauth_ac_')
    expect(location).toContain('state=csrf-state')
  })

  it('redirects with access_denied on denial per RFC 6749 §4.1.2.1', async () => {
    const req = makeReq({ ...VALID_BODY, decision: 'deny' })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('error=access_denied')
    expect(res.headers.get('Location')).toContain('state=csrf-state')
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('returns 400 for unknown decision', async () => {
    const res = await makeConsentHandler()(makeReq({ ...VALID_BODY, decision: 'maybe' }) as never)
    expect(res.status).toBe(400)
  })

  it('returns 400 when required fields are missing', async () => {
    const res = await makeConsentHandler()(makeReq({ decision: 'approve' }) as never)
    expect(res.status).toBe(400)
  })

  it('returns 400 for unknown client_id', async () => {
    const req = makeReq(VALID_BODY)
    req.payload.find = vi.fn().mockResolvedValue({ docs: [] })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_client')
  })

  it('returns 400 when redirect_uri is not registered', async () => {
    const res = await makeConsentHandler()(
      makeReq({ ...VALID_BODY, redirect_uri: 'https://attacker.example.com/steal' }) as never,
    )
    expect(res.status).toBe(400)
  })

  it('returns 405 for non-POST', async () => {
    const res = await makeConsentHandler()(makeReq(VALID_BODY, 'GET') as never)
    expect(res.status).toBe(405)
  })

  it('issues code without state when state is absent (state is optional per OAuth 2.1)', async () => {
    const { state: _omit, ...bodyWithoutState } = VALID_BODY
    const res = await makeConsentHandler()(makeReq(bodyWithoutState) as never)
    expect(res.status).toBe(302)
    const location = res.headers.get('Location') ?? ''
    expect(location).toContain('code=pmoauth_ac_')
    expect(location).not.toContain('state=')
  })

  it('rejects a replayed csrf_nonce with 400 (single-use enforcement)', async () => {
    const req = makeReq(VALID_BODY)
    req.payload.update = vi.fn().mockResolvedValue({ docs: [] })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_request')
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('rejects missing csrf_nonce with 400', async () => {
    const { csrf_nonce: _omit, ...bodyWithoutNonce } = VALID_BODY
    const res = await makeConsentHandler()(makeReq(bodyWithoutNonce) as never)
    expect(res.status).toBe(400)
  })

  it('rejects missing csrf_token with 400', async () => {
    const { csrf_token: _omit, ...bodyWithoutCsrf } = VALID_BODY
    const res = await makeConsentHandler()(makeReq(bodyWithoutCsrf) as never)
    expect(res.status).toBe(400)
  })

  it('rejects tampered csrf_token with 400', async () => {
    const res = await makeConsentHandler()(makeReq({ ...VALID_BODY, csrf_token: 'deadbeef'.repeat(8) }) as never)
    expect(res.status).toBe(400)
  })

  it('rejects forged csrf_token computed for different parameters with 400', async () => {
    const forgery = makeCsrfToken('attacker', 'client-1', REGISTERED_URI, CODE_CHALLENGE)
    const res = await makeConsentHandler()(makeReq({ ...VALID_BODY, csrf_token: forgery }) as never)
    expect(res.status).toBe(400)
  })

  it('rejects an unauthenticated consent POST with 401 (session binding)', async () => {
    const req = makeReq(VALID_BODY, 'POST', null)
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(401)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('access_denied')
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('rejects when the form user_id does not match the session user with 403', async () => {
    // Token is minted for the *session* user, so an attacker who swaps in a
    // victim user_id cannot make it validate; the explicit mismatch check fires
    // first and returns 403.
    const req = makeReq({ ...VALID_BODY, user_id: 'victim-99' }, 'POST', { id: 'user-1' })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(403)
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('rejects a csrf_token minted for a different user than the session with 400', async () => {
    // A token bound to a victim under their own session, replayed by an
    // attacker whose session is user-1, must not validate.
    const victimToken = makeCsrfToken('victim-99', 'client-1', REGISTERED_URI, CODE_CHALLENGE)
    const req = makeReq({ ...VALID_BODY, csrf_token: victimToken }, 'POST', { id: 'user-1' })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(400)
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('mints the auth code for the SESSION user, ignoring the body user_id', async () => {
    // No user_id in the body (so the mismatch guard is skipped); the code must
    // still be minted for the authenticated session user.
    const { user_id: _omit, ...bodyNoUser } = VALID_BODY
    const req = makeReq(bodyNoUser, 'POST', { id: 'user-1' })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(302)
    expect(req.payload.create).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'oauth-auth-codes',
        data: expect.objectContaining({ userId: 'user-1' }),
      }),
    )
  })

  it('accepts a numeric user_id that matches the session (integer Payload IDs)', async () => {
    // Payload IDs are often integers; a JSON client may echo user_id back as a
    // number. It must not spuriously 403 against the String(session id) — the
    // body value is coerced before comparison.
    const numericBody = {
      ...VALID_BODY,
      user_id: 123,
      csrf_token: makeCsrfToken('123', 'client-1', REGISTERED_URI, CODE_CHALLENGE),
    }
    const req = makeReq(numericBody, 'POST', { id: 123 })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(302)
    expect(req.payload.create).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'oauth-auth-codes',
        data: expect.objectContaining({ userId: '123' }),
      }),
    )
  })

  it('rejects an expired csrf_token with 400', async () => {
    const stale = makeCsrfToken('user-1', 'client-1', REGISTERED_URI, CODE_CHALLENGE, Date.now() - 11 * 60 * 1000)
    const req = makeReq({ ...VALID_BODY, csrf_token: stale }, 'POST', { id: 'user-1' })
    const res = await makeConsentHandler()(req as never)
    expect(res.status).toBe(400)
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('rejects a tampered scope token with 400 when scope enforcement is active', async () => {
    const req = makeReq({ ...VALID_BODY, scope: 'evil:all' }, 'POST', { id: 'user-1' })
    const res = await makeConsentHandler(300, '', MCP_OPTIONS)(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_scope')
    expect(req.payload.create).not.toHaveBeenCalled()
  })

  it('allows a valid scope token when scope enforcement is active', async () => {
    const req = makeReq({ ...VALID_BODY, scope: 'posts:read' })
    const res = await makeConsentHandler(300, '', MCP_OPTIONS)(req as never)
    expect(res.status).toBe(302)
    expect(req.payload.create).toHaveBeenCalled()
  })
})

describe('makeConsentHandler — RFC 9207 iss on the deny response', () => {
  const ISSUER = 'https://cms.example.com'

  it('includes iss when the user denies', async () => {
    // The success redirect has always carried iss; the deny redirect is just as
    // much an authorization response (RFC 9207 §2 covers error responses too).
    // A client honouring our advertised support must otherwise reject it (§2.4),
    // turning "the user pressed Deny" into a protocol violation.
    const res = await makeConsentHandler(300, ISSUER)(
      makeReq({ ...VALID_BODY, decision: 'deny' }) as never,
    )
    const url = new URL(res.headers.get('Location') ?? '')
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('iss')).toBe(ISSUER)
    expect(url.searchParams.get('state')).toBe('csrf-state')
  })

  it('matches the iss the approve redirect sends', async () => {
    const approved = await makeConsentHandler(300, ISSUER)(makeReq(VALID_BODY) as never)
    const denied = await makeConsentHandler(300, ISSUER)(
      makeReq({ ...VALID_BODY, decision: 'deny' }) as never,
    )
    const issOf = (r: Response) => new URL(r.headers.get('Location') ?? '').searchParams.get('iss')
    expect(issOf(denied)).toBe(issOf(approved))
  })

  it('omits iss entirely when no issuer is configured', async () => {
    const res = await makeConsentHandler()(makeReq({ ...VALID_BODY, decision: 'deny' }) as never)
    expect(new URL(res.headers.get('Location') ?? '').searchParams.has('iss')).toBe(false)
  })
})
