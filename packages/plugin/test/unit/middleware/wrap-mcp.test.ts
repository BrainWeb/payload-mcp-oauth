import { describe, expect, it, vi } from 'vitest'
import { installOverrideAuth, wrapMcpEndpointHandler } from '../../../src/middleware/wrap-mcp.js'
import { OAuthInvalidTokenError } from '../../../src/types.js'
import { UnauthorizedError } from 'payload'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const TEST_ISSUER = 'https://example.com'
const TEST_PRM_URL = `${TEST_ISSUER}/.well-known/oauth-protected-resource`

describe('wrapMcpEndpointHandler', () => {
  it('calls the original handler and returns its response', async () => {
    const original = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    expect(original).toHaveBeenCalledOnce()
    expect(res.status).toBe(200)
  })

  it('converts OAuthInvalidTokenError to 401 with WWW-Authenticate header including resource_metadata', async () => {
    const original = vi.fn().mockRejectedValue(new OAuthInvalidTokenError())
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    expect(res.status).toBe(401)
    const www = res.headers.get('WWW-Authenticate') ?? ''
    expect(www).toContain('Bearer error="invalid_token"')
    expect(www).toContain(`resource_metadata="${TEST_PRM_URL}"`)
  })

  it('adds resource_metadata to 401 responses from the underlying handler', async () => {
    const original = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 401,
        headers: { 'WWW-Authenticate': 'Bearer realm="test"' },
      }),
    )
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    expect(res.status).toBe(401)
    const www = res.headers.get('WWW-Authenticate') ?? ''
    expect(www).toContain('Bearer realm="test"')
    expect(www).toContain(`resource_metadata="${TEST_PRM_URL}"`)
  })

  it('adds resource_metadata to bare 401 with no WWW-Authenticate', async () => {
    const original = vi.fn().mockResolvedValue(new Response(null, { status: 401 }))
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toContain(`resource_metadata="${TEST_PRM_URL}"`)
  })

  it('does not duplicate resource_metadata if already present', async () => {
    const existing = `Bearer resource_metadata="${TEST_PRM_URL}"`
    const original = vi.fn().mockResolvedValue(
      new Response(null, { status: 401, headers: { 'WWW-Authenticate': existing } }),
    )
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    const www = res.headers.get('WWW-Authenticate') ?? ''
    expect(www.split('resource_metadata=').length - 1).toBe(1)
  })

  it('converts Payload UnauthorizedError to 401 with resource_metadata challenge (no error code)', async () => {
    const original = vi.fn().mockRejectedValue(new UnauthorizedError())
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    const res = await wrapped({} as never)
    expect(res.status).toBe(401)
    const www = res.headers.get('WWW-Authenticate') ?? ''
    expect(www).toContain(`resource_metadata="${TEST_PRM_URL}"`)
    expect(www).not.toContain('error=')
  })

  it('rethrows non-OAuth errors', async () => {
    const original = vi.fn().mockRejectedValue(new Error('DB connection failed'))
    const wrapped = wrapMcpEndpointHandler(original, TEST_ISSUER)
    await expect(wrapped({} as never)).rejects.toThrow('DB connection failed')
  })
})

describe('installOverrideAuth', () => {
  function makePayload(user: unknown = { id: 'user-1', email: 'a@b.com' }) {
    return {
      find: vi.fn().mockResolvedValue({ docs: [] }),
      findByID: vi.fn().mockResolvedValue(user),
    }
  }

  it('sets overrideAuth on mcpPluginOptions', () => {
    const opts = {} as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')
    expect(typeof opts.overrideAuth).toBe('function')
  })

  it('delegates to getDefaultMcpAccessSettings for non-pmoauth tokens', async () => {
    const opts = {} as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')
    const getDefault = vi.fn().mockResolvedValue({ user: { id: 'u1' } })
    const req = {
      headers: { get: vi.fn().mockReturnValue('Bearer api-key-abc123') },
      payload: makePayload(),
    }
    await opts.overrideAuth!(req as never, getDefault)
    expect(getDefault).toHaveBeenCalledOnce()
  })

  it('delegates to getDefaultMcpAccessSettings when no Authorization header', async () => {
    const opts = {} as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')
    const getDefault = vi.fn().mockResolvedValue({ user: { id: 'u1' } })
    const req = {
      headers: { get: vi.fn().mockReturnValue(null) },
      payload: makePayload(),
    }
    await opts.overrideAuth!(req as never, getDefault)
    expect(getDefault).toHaveBeenCalledOnce()
  })

  it('throws OAuthInvalidTokenError for an unknown pmoauth_ token', async () => {
    const opts = {} as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')
    // find returns no docs → validateAccessToken returns null
    const payload = {
      find: vi.fn().mockResolvedValue({ docs: [] }),
      findByID: vi.fn(),
    }
    const req = {
      headers: { get: vi.fn().mockReturnValue('Bearer pmoauth_at_unknowntoken12345678901234567890123') },
      payload,
    }
    const getDefault = vi.fn()
    await expect(opts.overrideAuth!(req as never, getDefault)).rejects.toThrow(OAuthInvalidTokenError)
    expect(getDefault).not.toHaveBeenCalled()
  })

  it('resolves a legacy empty-capability token with an empty scope to the full operator grant', async () => {
    const opts = {
      collections: {
        users: { enabled: { find: true, create: false, update: true, delete: false } },
        'oauth-clients': { enabled: true },
      },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const tokenDoc = {
      id: 'tok-1',
      tokenHash: 'anyhash',
      tokenType: 'access',
      userId: 'user-1',
      clientId: 'client-1',
      // Tokens issued up to 0.4.0 stored `{}` with an omitted scope (#75). The
      // empty SCOPE is what identifies them as full grants — not the empty
      // capability set, which on its own is ambiguous.
      scope: '',
      capabilities: {},
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      revokedAt: null,
    }
    const payload = {
      find: vi.fn().mockResolvedValue({ docs: [tokenDoc] }),
      findByID: vi.fn().mockResolvedValue({ id: 'user-1', email: 'a@b.com' }),
      update: vi.fn().mockResolvedValue({}),
    }
    const req = {
      headers: { get: vi.fn().mockReturnValue('Bearer pmoauth_at_sometoken12345678901234567890123') },
      payload,
    }
    const getDefault = vi.fn()
    const result = await opts.overrideAuth!(req as never, getDefault)

    expect(result.user).toBeDefined()
    expect((result as Record<string, unknown>).users).toEqual({ find: true, create: false, update: true, delete: false })
    expect((result as Record<string, unknown>).oauthClients).toEqual({ find: true, create: true, update: true, delete: true })
    expect(getDefault).not.toHaveBeenCalled()
  })

  function makeTokenReq(tokenDoc: Record<string, unknown>) {
    const payload = {
      find: vi.fn().mockResolvedValue({ docs: [tokenDoc] }),
      findByID: vi.fn().mockResolvedValue({ id: 'user-1', email: 'a@b.com' }),
      update: vi.fn().mockResolvedValue({}),
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    }
    return {
      headers: { get: vi.fn().mockReturnValue('Bearer pmoauth_at_sometoken12345678901234567890123') },
      payload,
    }
  }

  function makeAccessTokenDoc(overrides: Record<string, unknown> = {}) {
    return {
      id: 'tok-caps',
      tokenHash: 'anyhash',
      tokenType: 'access',
      userId: 'user-1',
      clientId: 'client-1',
      scope: 'posts:read',
      capabilities: { posts: { find: true } },
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      revokedAt: null,
      ...overrides,
    }
  }

  it('honours a stored narrowed grant without widening it to the full set', async () => {
    const opts = {
      collections: { posts: { enabled: true }, media: { enabled: true } },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(makeAccessTokenDoc())
    const result = (await opts.overrideAuth!(req as never, vi.fn())) as Record<string, unknown>

    expect(result['posts']).toEqual({ find: true })
    // media was never granted, so it must not appear even though it is enabled.
    expect(result['media']).toBeUndefined()
  })

  it('narrows a stored grant to the live config when the operator disables an operation', async () => {
    // The privilege-retention case: the token was issued while posts:delete was
    // enabled. The operator has since restricted posts to reads only, and that
    // must take effect on the very next request — not when the token expires.
    const opts = {
      collections: { posts: { enabled: { find: true } as never } },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(
      makeAccessTokenDoc({ scope: 'posts:read posts:delete', capabilities: { posts: { find: true, delete: true } } }),
    )
    const result = (await opts.overrideAuth!(req as never, vi.fn())) as Record<string, unknown>

    expect(result['posts']).toEqual({ find: true })
  })

  it('grants nothing when the operator has disabled every collection the token names', async () => {
    const opts = { collections: {} } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(makeAccessTokenDoc())
    const result = (await opts.overrideAuth!(req as never, vi.fn())) as Record<string, unknown>

    // Authentication still succeeds — the user is real — but the grant is empty.
    expect(result['user']).toBeDefined()
    expect(result['posts']).toBeUndefined()
  })

  it('narrows a legacy full grant to the live config too', async () => {
    const opts = {
      collections: { posts: { enabled: { find: true } as never } },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(makeAccessTokenDoc({ scope: '', capabilities: {} }))
    const result = (await opts.overrideAuth!(req as never, vi.fn())) as Record<string, unknown>

    expect(result['posts']).toEqual({ find: true })
  })

  it('fails closed on a contradictory row: no stored capabilities but a non-empty scope', async () => {
    // No issuance path can produce this — a valid scope always yields at least
    // one capability and an invalid one is refused at the token endpoint — so
    // the row is corrupt. Refuse rather than guess; the 401 prompts the client
    // to re-authorize, which rewrites the record correctly.
    const opts = {
      collections: { posts: { enabled: true } },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(makeAccessTokenDoc({ scope: 'posts:read', capabilities: {} }))
    await expect(opts.overrideAuth!(req as never, vi.fn())).rejects.toThrow(OAuthInvalidTokenError)
  })

  it('does not log the requested scope check as a silent widening', async () => {
    const opts = {
      collections: { posts: { enabled: true } },
    } as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const req = makeTokenReq(makeAccessTokenDoc({ scope: 'posts:read', capabilities: {} }))
    await expect(opts.overrideAuth!(req as never, vi.fn())).rejects.toThrow(OAuthInvalidTokenError)
    expect(req.payload.logger.error).toHaveBeenCalledWith(expect.stringContaining('refusing'))
  })

  it('sets user.collection and user._strategy on the returned user', async () => {
    const opts = {} as Parameters<typeof installOverrideAuth>[0]
    installOverrideAuth(opts, 'users')

    const tokenDoc = {
      id: 'tok-2',
      tokenHash: 'anyhash2',
      tokenType: 'access',
      userId: 'user-2',
      clientId: 'client-1',
      scope: '',
      capabilities: {},
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      revokedAt: null,
    }
    const payload = {
      find: vi.fn().mockResolvedValue({ docs: [tokenDoc] }),
      findByID: vi.fn().mockResolvedValue({ id: 'user-2', email: 'b@c.com' }),
      update: vi.fn().mockResolvedValue({}),
    }
    const req = {
      headers: { get: vi.fn().mockReturnValue('Bearer pmoauth_at_anothertoken1234567890123456789012') },
      payload,
    }
    const result = await opts.overrideAuth!(req as never, vi.fn())
    const u = result.user as Record<string, unknown>
    expect(u['collection']).toBe('users')
    expect(u['_strategy']).toBe('local-jwt')
  })
})
