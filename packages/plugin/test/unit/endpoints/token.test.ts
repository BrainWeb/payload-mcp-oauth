import crypto from 'crypto'
import { describe, expect, it, vi } from 'vitest'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { makeTokenHandler } from '../../../src/endpoints/token.js'
import { hashToken } from '../../../src/lib/token-storage.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const MCP_OPTIONS: MCPPluginConfig = {
  collections: { posts: { enabled: true } },
}

// RFC 7636 §Appendix B test vector (43 chars of the unreserved set)
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const CHALLENGE = crypto.createHash('sha256').update(VERIFIER).digest('base64url')
const VALID_REFRESH = 'pmoauth_rt_Rv8xKq3mN2pLs9nW4tF2qMr6kB1uJ7pabc'

function makeCodeDoc(overrides: Record<string, unknown> = {}) {
  return {
    id: 'code-doc-1',
    clientId: 'client-1',
    userId: 'user-1',
    redirectUri: 'https://example.com/cb',
    scope: 'posts:read',
    codeChallenge: CHALLENGE,
    codeChallengeMethod: 'S256',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    consumedAt: null,
    ...overrides,
  }
}

function makeRefreshDoc(overrides: Record<string, unknown> = {}) {
  return {
    id: 'refresh-doc-1',
    tokenHash: hashToken(VALID_REFRESH),
    tokenType: 'refresh',
    clientId: 'client-1',
    userId: 'user-1',
    scope: 'posts:read',
    capabilities: {},
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    revokedAt: null,
    ...overrides,
  }
}

function makeReq(body: unknown, findDocs: unknown[] = [], method = 'POST') {
  return {
    method,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn(),
    payload: {
      find: vi.fn().mockResolvedValue({ docs: findDocs }),
      create: vi.fn().mockResolvedValue({ id: 'new-doc' }),
      // Bulk update (where) returns BulkOperationResult { docs, errors }
      update: vi.fn().mockResolvedValue({ docs: [{ id: 'consumed-doc' }] }),
    },
  }
}

describe('makeTokenHandler — authorization_code grant', () => {
  it('returns a token pair on valid auth code exchange', async () => {
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc()],
    )
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(200)
    const b = await res.json() as Record<string, unknown>
    expect(b['access_token']).toMatch(/^pmoauth_at_/)
    expect(b['refresh_token']).toMatch(/^pmoauth_rt_/)
  })

  it('stores narrowed capabilities derived from the auth code scope (scope enforcement)', async () => {
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: 'posts:read' })],
    )
    await makeTokenHandler(MCP_OPTIONS)(req as never)
    // issueTokenPair is called via payload.create — verify the narrowed capabilities were passed
    const createCall = req.payload.create.mock.calls.find(
      (c: [{ collection: string }]) => c[0].collection === 'oauth-tokens',
    )
    expect(createCall).toBeDefined()
    const data = (createCall as [{ data: Record<string, unknown> }])[0].data
    expect(data['capabilities']).toEqual({ posts: { find: true } })
  })

  it('stores the full operator grant when scope is absent (#75)', async () => {
    // Regression test for #75. Claude.ai's Custom Connector completes the flow
    // with no scope, so this is the NORMAL path, not an edge case. Versions up
    // to 0.4.0 persisted `capabilities: {}` here — a record that reads as "no
    // permissions" for anything inspecting the row, while requests succeeded
    // with full access through a fallback in overrideAuth.
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: '' })],
    )
    await makeTokenHandler(MCP_OPTIONS)(req as never)
    const createCall = req.payload.create.mock.calls.find(
      (c: [{ collection: string }]) => c[0].collection === 'oauth-tokens',
    )
    const data = (createCall as [{ data: Record<string, unknown> }])[0].data
    expect(data['capabilities']).toEqual({
      posts: { find: true, create: true, update: true, delete: true },
    })
  })

  it('records the full grant on BOTH the access and the refresh token', async () => {
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: '' })],
    )
    await makeTokenHandler(MCP_OPTIONS)(req as never)
    const tokenRows = req.payload.create.mock.calls
      .filter((c: [{ collection: string }]) => c[0].collection === 'oauth-tokens')
      .map((c: [{ data: Record<string, unknown> }]) => c[0].data)
    expect(tokenRows).toHaveLength(2)
    for (const row of tokenRows) {
      expect(row['capabilities']).not.toEqual({})
    }
  })

  it('stores exactly the requested capabilities when a scope IS supplied', async () => {
    // The narrowed grant must not be widened to the full set by the #75 fix.
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: 'posts:read' })],
    )
    await makeTokenHandler(MCP_OPTIONS)(req as never)
    const createCall = req.payload.create.mock.calls.find(
      (c: [{ collection: string }]) => c[0].collection === 'oauth-tokens',
    )
    const data = (createCall as [{ data: Record<string, unknown> }])[0].data
    expect(data['capabilities']).toEqual({ posts: { find: true } })
  })

  it('stores no capabilities when the handler is built without mcpPluginOptions', async () => {
    // Direct construction with no MCP options has nothing to resolve a grant
    // from; the row stays empty and overrideAuth's legacy path handles it.
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: '' })],
    )
    await makeTokenHandler()(req as never)
    const createCall = req.payload.create.mock.calls.find(
      (c: [{ collection: string }]) => c[0].collection === 'oauth-tokens',
    )
    const data = (createCall as [{ data: Record<string, unknown> }])[0].data
    expect(data['capabilities']).toEqual({})
  })

  it('rejects with invalid_scope when the code scope is no longer grantable (no full-grant escalation)', async () => {
    // Scope was valid at /authorize but the collection is now disabled (here
    // 'secrets' is absent from MCP_OPTIONS), so scopeToCapabilities returns
    // kind:'invalid'. The exchange must be rejected outright rather than issue
    // a token whose stored grant says nothing about what it may do.
    const authCode = 'pmoauth_ac_' + crypto.randomBytes(32).toString('base64url')
    const req = makeReq(
      { grant_type: 'authorization_code', code: authCode, client_id: 'client-1', redirect_uri: 'https://example.com/cb', code_verifier: VERIFIER },
      [makeCodeDoc({ scope: 'secrets:read' })],
    )
    const res = await makeTokenHandler(MCP_OPTIONS)(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_scope')
    // No token row was created.
    const createdToken = req.payload.create.mock.calls.find(
      (c: [{ collection: string }]) => c[0].collection === 'oauth-tokens',
    )
    expect(createdToken).toBeUndefined()
  })

  it('returns invalid_grant for bad code', async () => {
    const req = makeReq(
      { grant_type: 'authorization_code', code: 'pmoauth_ac_bad', client_id: 'c1', redirect_uri: 'https://a.com', code_verifier: VERIFIER },
      [],
    )
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_grant')
  })

  it('returns invalid_request when required fields missing', async () => {
    const req = makeReq({ grant_type: 'authorization_code', code: 'pmoauth_ac_x' }, [])
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_request')
  })

  it('returns invalid_request for code_verifier that violates RFC 7636 (too short)', async () => {
    const req = makeReq(
      { grant_type: 'authorization_code', code: 'pmoauth_ac_x', client_id: 'c1', redirect_uri: 'https://a.com', code_verifier: 'short' },
      [],
    )
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_request')
  })
})

describe('makeTokenHandler — refresh_token grant', () => {
  it('returns a new token pair on valid refresh', async () => {
    const req = makeReq(
      { grant_type: 'refresh_token', refresh_token: VALID_REFRESH, client_id: 'client-1' },
      [makeRefreshDoc()],
    )
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(200)
    expect(((await res.json()) as Record<string, unknown>)['access_token']).toMatch(/^pmoauth_at_/)
  })

  it('returns invalid_grant for expired refresh token', async () => {
    const req = makeReq(
      { grant_type: 'refresh_token', refresh_token: VALID_REFRESH, client_id: 'client-1' },
      [makeRefreshDoc({ expiresAt: new Date(Date.now() - 1000).toISOString() })],
    )
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_grant')
  })

  it('returns invalid_request when refresh_token missing', async () => {
    const req = makeReq({ grant_type: 'refresh_token', client_id: 'c1' }, [])
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
  })
})

describe('makeTokenHandler — edge cases', () => {
  it('returns unsupported_grant_type for unknown grant', async () => {
    const req = makeReq({ grant_type: 'client_credentials' }, [])
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('unsupported_grant_type')
  })

  it('returns invalid_request when grant_type is absent', async () => {
    const req = makeReq({}, [])
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(400)
    expect(((await res.json()) as Record<string, unknown>)['error']).toBe('invalid_request')
  })

  it('returns 405 for non-POST', async () => {
    const req = makeReq({}, [], 'GET')
    const res = await makeTokenHandler()(req as never)
    expect(res.status).toBe(405)
  })
})
