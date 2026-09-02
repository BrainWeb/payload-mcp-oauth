import { describe, expect, it } from 'vitest'
import { buildPlugin } from '../../../src/plugin.js'
import { PayloadMcpOAuthError } from '../../../src/types.js'
import type { PayloadMcpOAuthConfig } from '../../../src/types.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const MCP_ENDPOINT = { path: '/mcp', method: 'post' as const, handler: async () => new Response('ok') }

function makeConfig(endpointOverrides: unknown[] = [MCP_ENDPOINT]) {
  return {
    endpoints: endpointOverrides as import('payload').Endpoint[],
    collections: [],
  } as import('payload').Config
}

function makeOptions(overrides: Partial<PayloadMcpOAuthConfig> = {}): PayloadMcpOAuthConfig {
  return {
    issuer: 'https://cms.example.com',
    mcpPluginOptions: {},
    ...overrides,
  }
}

describe('buildPlugin — config validation', () => {
  it('throws MISSING_ISSUER when issuer is absent', () => {
    expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: '' }))).toThrow(PayloadMcpOAuthError)
  })

  it('throws INVALID_ISSUER when issuer is not a URL', () => {
    expect(() =>
      buildPlugin(makeConfig(), makeOptions({ issuer: 'not-a-url' })),
    ).toThrow(PayloadMcpOAuthError)
  })

  it('throws MISSING_MCP_OPTIONS when mcpPluginOptions is absent', () => {
    expect(() =>
      buildPlugin(makeConfig(), makeOptions({ mcpPluginOptions: undefined as never })),
    ).toThrow(PayloadMcpOAuthError)
  })
})

describe('buildPlugin — production hardening', () => {
  const withEnv = (env: Record<string, string | undefined>, fn: () => void) => {
    const prev: Record<string, string | undefined> = {}
    for (const k of Object.keys(env)) {
      prev[k] = process.env[k]
      if (env[k] === undefined) delete process.env[k]
      else process.env[k] = env[k]
    }
    try {
      fn()
    } finally {
      for (const k of Object.keys(env)) {
        if (prev[k] === undefined) delete process.env[k]
        else process.env[k] = prev[k]
      }
    }
  }

  it('throws when the issuer is not https in production', () => {
    withEnv({ NODE_ENV: 'production' }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://cms.example.com' }))).toThrow(/https/i)
    })
  })

  it('allows an https issuer in production', () => {
    withEnv({ NODE_ENV: 'production' }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'https://cms.example.com' }))).not.toThrow()
    })
  })

  it('allows an http://localhost issuer in production (#71 — local `next build`)', () => {
    // `next build` sets NODE_ENV=production unconditionally, so this fired on a
    // routine local production build with the standard dev server URL.
    withEnv({ NODE_ENV: 'production' }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://localhost:3000' }))).not.toThrow()
    })
  })

  it('allows http://127.0.0.1 and http://[::1] issuers in production', () => {
    withEnv({ NODE_ENV: 'production' }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://127.0.0.1:3000' }))).not.toThrow()
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://[::1]:3000' }))).not.toThrow()
    })
  })

  it('still rejects a non-loopback http issuer in production', () => {
    withEnv({ NODE_ENV: 'production' }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://cms.example.com' }))).toThrow(/https/i)
      // A hostname that merely contains "localhost" is not loopback.
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://localhost.evil.com' }))).toThrow(/https/i)
      expect(() => buildPlugin(makeConfig(), makeOptions({ issuer: 'http://notlocalhost' }))).toThrow(/https/i)
    })
  })

  it('does NOT relax the pepper requirement for a loopback issuer', () => {
    // The HTTPS exemption is about a transport that does not exist on loopback.
    // The pepper protects data at rest, so it stays required — and the message
    // has to name the local-build case, or #71's reporter just hits this wall
    // instead of the previous one.
    withEnv({ NODE_ENV: 'production', PMOAUTH_TOKEN_PEPPER: undefined }, () => {
      expect(() =>
        buildPlugin(makeConfig(), makeOptions({ issuer: 'http://localhost:3000' })),
      ).toThrow(/next build/)
    })
  })

  it('throws MISSING_PEPPER when no pepper is set outside development/test', () => {
    withEnv({ NODE_ENV: 'production', PMOAUTH_TOKEN_PEPPER: undefined }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions())).toThrow(/PMOAUTH_TOKEN_PEPPER/)
    })
  })

  it('allows the dev fallback when NODE_ENV=test and no pepper is set', () => {
    withEnv({ NODE_ENV: 'test', PMOAUTH_TOKEN_PEPPER: undefined }, () => {
      expect(() => buildPlugin(makeConfig(), makeOptions())).not.toThrow()
    })
  })
})

describe('buildPlugin — order detection (T5.3)', () => {
  it('throws PLUGIN_ORDER when no /mcp endpoint is present', () => {
    expect(() => buildPlugin(makeConfig([]), makeOptions())).toThrow(PayloadMcpOAuthError)
  })

  it('accepts config when /mcp endpoint exists', () => {
    expect(() => buildPlugin(makeConfig([MCP_ENDPOINT]), makeOptions())).not.toThrow()
  })
})

describe('buildPlugin — collections (T5.5)', () => {
  it('adds the three OAuth collections', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    const slugs = result.collections?.map((c) => c.slug)
    expect(slugs).toContain('oauth-clients')
    expect(slugs).toContain('oauth-auth-codes')
    expect(slugs).toContain('oauth-tokens')
  })

  it('preserves existing collections', () => {
    const existing = { slug: 'posts', fields: [] }
    const config = makeConfig()
    config.collections = [existing]
    const result = buildPlugin(config, makeOptions())
    expect(result.collections?.map((c) => c.slug)).toContain('posts')
  })

  it('opts every OAuth collection out of document-locking (lockDocuments: false)', () => {
    // Keeps the plugin's collections out of `payload_locked_documents_rels`, so
    // installing it never forces a rebuild of that table — which fails on SQLite
    // dev push when added to an already-pushed DB (no such column: oauth_*_id).
    const result = buildPlugin(makeConfig(), makeOptions())
    const oauthSlugs = ['oauth-clients', 'oauth-auth-codes', 'oauth-tokens', 'oauth-csrf-nonces']
    for (const slug of oauthSlugs) {
      const c = result.collections?.find((col) => col.slug === slug)
      expect(c, `${slug} should be registered`).toBeTruthy()
      expect(c?.lockDocuments, `${slug} must set lockDocuments: false`).toBe(false)
    }
  })
})

describe('buildPlugin — disabled / no-op', () => {
  it('disabled: true keeps the collections but adds no OAuth endpoints', () => {
    const result = buildPlugin(makeConfig(), makeOptions({ disabled: true }))
    const slugs = result.collections?.map((c) => c.slug) ?? []
    expect(slugs).toContain('oauth-clients')
    expect(slugs).toContain('oauth-tokens')
    const paths = result.endpoints?.map((e) => e.path) ?? []
    expect(paths).not.toContain('/oauth/token')
    expect(paths).not.toContain('/.well-known/oauth-authorization-server')
  })

  it('treats a disabled MCP plugin as disabled — no endpoints, and does NOT throw without /mcp', () => {
    // mcp disabled ⇒ it registers no /mcp endpoint; we must not throw PLUGIN_ORDER.
    const noEndpoints = makeConfig([])
    const opts = makeOptions({ mcpPluginOptions: { disabled: true } as never })
    expect(() => buildPlugin(noEndpoints, opts)).not.toThrow()
    const result = buildPlugin(makeConfig([]), opts)
    expect(result.collections?.map((c) => c.slug)).toContain('oauth-clients')
    expect(result.endpoints?.some((e) => e.path === '/oauth/token')).toBeFalsy()
  })

  it('disabled path skips issuer/pepper validation (returns before resolveConfig)', () => {
    expect(() => buildPlugin(makeConfig(), makeOptions({ disabled: true, issuer: '' }))).not.toThrow()
  })

  it('still throws PLUGIN_ORDER when ENABLED and no /mcp endpoint exists', () => {
    expect(() => buildPlugin(makeConfig([]), makeOptions())).toThrow(PayloadMcpOAuthError)
  })

  it('payloadMcpOAuth does NOT install overrideAuth when disabled', async () => {
    const { payloadMcpOAuth } = await import('../../../src/index.js')
    const mcpOpts = {}
    payloadMcpOAuth(makeOptions({ disabled: true, mcpPluginOptions: mcpOpts }))
    expect((mcpOpts as Record<string, unknown>)['overrideAuth']).toBeUndefined()
  })

  it('payloadMcpOAuth does NOT install overrideAuth when the MCP plugin is disabled', async () => {
    const { payloadMcpOAuth } = await import('../../../src/index.js')
    const mcpOpts = { disabled: true }
    payloadMcpOAuth(makeOptions({ mcpPluginOptions: mcpOpts as never }))
    expect((mcpOpts as Record<string, unknown>)['overrideAuth']).toBeUndefined()
  })
})

describe('buildPlugin — admin access gate', () => {
  type AccessFn = (args: { req: { user: unknown } }) => unknown
  const coll = (result: import('payload').Config, slug: string) =>
    result.collections?.find((c) => c.slug === slug)
  const adminReq = (collection = 'users') => ({ req: { user: { id: 'u1', collection } } })

  it('opens read/update/delete on oauth-clients to admin-collection users, denies others', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    const access = coll(result, 'oauth-clients')?.access
    for (const op of ['read', 'update', 'delete'] as const) {
      const fn = access?.[op] as AccessFn
      expect(fn(adminReq()), `${op} should allow admin`).toBe(true)
      expect(fn({ req: { user: null } }), `${op} should deny anon`).toBeFalsy()
      expect(fn(adminReq('customers')), `${op} should deny other collection`).toBe(false)
    }
  })

  it('keeps create denied on oauth-clients (clients self-register via DCR)', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    const create = coll(result, 'oauth-clients')?.access?.create as AccessFn
    expect(create(adminReq())).toBe(false)
  })

  it('applies the same gate to oauth-tokens read', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    const read = coll(result, 'oauth-tokens')?.access?.read as AccessFn
    expect(read(adminReq())).toBe(true)
    expect(read({ req: { user: null } })).toBeFalsy()
  })

  it('uses the configured userCollection in the default gate', () => {
    const result = buildPlugin(makeConfig(), makeOptions({ userCollection: 'admins' }))
    const read = coll(result, 'oauth-clients')?.access?.read as AccessFn
    expect(read(adminReq('admins'))).toBe(true)
    expect(read(adminReq('users'))).toBe(false)
  })

  it('denies a non-admin member of the user collection when roles exist', () => {
    // The old default was collection membership alone, which in a single-`users`
    // app is effectively Boolean(req.user) — any logged-in end user could rewrite
    // a client's redirectUris or delete other users' tokens.
    const result = buildPlugin(makeConfig(), makeOptions())
    const read = coll(result, 'oauth-clients')?.access?.read as AccessFn

    expect(read({ req: { user: { collection: 'users', role: 'editor' } } })).toBe(false)
    expect(read({ req: { user: { collection: 'users', role: 'admin' } } })).toBe(true)
    expect(read({ req: { user: { collection: 'users', isAdmin: false } } })).toBe(false)
    expect(read({ req: { user: { collection: 'users', roles: ['editor'] } } })).toBe(false)
    expect(read({ req: { user: { collection: 'users', roles: ['admin'] } } })).toBe(true)
  })

  it('still authorises collection members when the collection has no role field', () => {
    // Default Payload starters have no role field — they must not be locked out.
    const result = buildPlugin(makeConfig(), makeOptions())
    const read = coll(result, 'oauth-clients')?.access?.read as AccessFn
    expect(read({ req: { user: { collection: 'users', email: 'op@example.com' } } })).toBe(true)
  })

  it('honours a custom adminAccess override', () => {
    let called = false
    const custom = () => {
      called = true
      return true
    }
    const result = buildPlugin(makeConfig(), makeOptions({ adminAccess: custom }))
    const read = coll(result, 'oauth-clients')?.access?.read as AccessFn
    expect(read(adminReq('anything'))).toBe(true)
    expect(called).toBe(true)
  })
})

describe('buildPlugin — endpoints (T5.5)', () => {
  it('registers all 7 OAuth endpoints', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    const paths = result.endpoints?.map((e) => e.path) ?? []
    expect(paths).toContain('/.well-known/oauth-authorization-server')
    expect(paths).toContain('/.well-known/oauth-protected-resource')
    expect(paths).toContain('/oauth/register')
    expect(paths).toContain('/oauth/authorize')
    expect(paths).toContain('/oauth/consent')
    expect(paths).toContain('/oauth/token')
    expect(paths).toContain('/oauth/revoke')
  })

  it('preserves the MCP endpoint (does not remove it)', () => {
    const result = buildPlugin(makeConfig(), makeOptions())
    expect(result.endpoints?.some((e) => e.path === '/mcp')).toBe(true)
  })

  it('wraps the MCP endpoint handler', () => {
    const opts = makeOptions()
    const result = buildPlugin(makeConfig(), opts)
    const mcpEndpoint = result.endpoints?.find((e) => e.path === '/mcp')
    // The handler should now be the wrapped version
    expect(typeof mcpEndpoint?.handler).toBe('function')
  })
})

describe('payloadMcpOAuth — overrideAuth installation (T5.4)', () => {
  it('sets overrideAuth on mcpPluginOptions eagerly (before plugin execution)', async () => {
    // overrideAuth must be set during payloadMcpOAuth() call, not deferred to plugin execution,
    // because Payload's definePlugin spreads mcpPluginOptions into a new object when it runs
    // the plugin — so mutations applied after that point are invisible to the MCP handler closure.
    const { payloadMcpOAuth } = await import('../../../src/index.js')
    const mcpOpts = {}
    payloadMcpOAuth(makeOptions({ mcpPluginOptions: mcpOpts }))
    expect(typeof (mcpOpts as Record<string, unknown>)['overrideAuth']).toBe('function')
  })
})

describe('payloadMcpOAuth — exported factory', () => {
  it('returns a Plugin function that transforms config', async () => {
    const { payloadMcpOAuth } = await import('../../../src/index.js')
    const plugin = payloadMcpOAuth(makeOptions())
    expect(typeof plugin).toBe('function')
    const result = plugin(makeConfig())
    expect(result).toBeTruthy()
  })
})

const AUTHORIZE_CLIENT = {
  id: 'client-doc-1',
  clientId: 'client-1',
  clientName: 'Test App',
  redirectUris: [{ uri: 'https://example.com/cb' }],
  isActive: true,
}

/** A fully valid /authorize request with NO session, so it reaches the login redirect. */
function makeAuthorizeReq(overrides: Record<string, unknown> = {}) {
  return {
    method: 'GET',
    query: {
      response_type: 'code',
      client_id: 'client-1',
      redirect_uri: 'https://example.com/cb',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    },
    user: null,
    url: 'https://cms.example.com/api/oauth/authorize?response_type=code&client_id=client-1',
    headers: new Headers(),
    payload: {
      find: async () => ({ docs: [AUTHORIZE_CLIENT] }),
      create: async () => ({ id: 'nonce-doc-1' }),
    },
    ...overrides,
  }
}

describe('buildPlugin — login redirect honours the app routes', () => {
  /** Drives the registered /oauth/authorize endpoint with no session. */
  async function authorizeUnauthenticated(config: import('payload').Config, options = makeOptions()) {
    const result = buildPlugin(config, options)
    const endpoint = (result.endpoints ?? []).find(
      (e) => e.path === '/oauth/authorize' && e.method === 'get',
    )
    expect(endpoint).toBeDefined()
    return endpoint!.handler(makeAuthorizeReq() as never) as Promise<Response>
  }

  it('uses the default /admin/login when no routes are configured', async () => {
    const res = await authorizeUnauthenticated(makeConfig())
    expect(res.headers.get('Location')).toContain('/admin/login?redirect=')
  })

  it('honours a custom routes.admin', async () => {
    // Previously hardcoded to '/admin', so a custom admin route sent users
    // mid-flow to a URL that does not exist.
    const config = { ...makeConfig(), routes: { admin: '/cms' } } as import('payload').Config
    const res = await authorizeUnauthenticated(config)
    expect(res.headers.get('Location')).toContain('/cms/login?redirect=')
  })

  it('honours a custom admin.routes.login', async () => {
    const config = {
      ...makeConfig(),
      admin: { routes: { login: '/sign-in' } },
    } as import('payload').Config
    const res = await authorizeUnauthenticated(config)
    expect(res.headers.get('Location')).toContain('/admin/sign-in?redirect=')
  })

  it('combines a custom admin route with a custom login route', async () => {
    const config = {
      ...makeConfig(),
      routes: { admin: '/cms' },
      admin: { routes: { login: '/sign-in' } },
    } as import('payload').Config
    const res = await authorizeUnauthenticated(config)
    expect(res.headers.get('Location')).toContain('/cms/sign-in?redirect=')
  })

  it('does not double the slash when the admin panel is mounted at /', async () => {
    const config = { ...makeConfig(), routes: { admin: '/' } } as import('payload').Config
    const res = await authorizeUnauthenticated(config)
    const location = res.headers.get('Location') ?? ''
    expect(location.startsWith('/login?redirect=')).toBe(true)
  })

  it('lets an explicit loginPath override the derived one', async () => {
    const config = { ...makeConfig(), routes: { admin: '/cms' } } as import('payload').Config
    const res = await authorizeUnauthenticated(config, makeOptions({ loginPath: '/portal/login' }))
    expect(res.headers.get('Location')).toContain('/portal/login?redirect=')
  })

  it('builds the post-login return path from routes.api', async () => {
    const config = { ...makeConfig(), routes: { api: '/cms-api' } } as import('payload').Config
    const result = buildPlugin(config, makeOptions())
    const endpoint = (result.endpoints ?? []).find(
      (e) => e.path === '/oauth/authorize' && e.method === 'get',
    )
    const res = (await endpoint!.handler(makeAuthorizeReq({ url: undefined }) as never)) as Response
    expect(decodeURIComponent(res.headers.get('Location') ?? '')).toContain('/cms-api/oauth/authorize')
  })
})

describe('buildPlugin — does not mutate the incoming config (#50)', () => {
  it('leaves the input endpoint objects untouched', () => {
    const originalHandler = async () => new Response('ok')
    const inputEndpoint = { path: '/mcp', method: 'post' as const, handler: originalHandler }
    const config = makeConfig([inputEndpoint])

    buildPlugin(config, makeOptions())

    // The returned config wraps the handler; the object we were given must not.
    expect(inputEndpoint.handler).toBe(originalHandler)
  })

  it('returns a NEW endpoint object carrying the wrapped handler', () => {
    const originalHandler = async () => new Response('ok')
    const inputEndpoint = { path: '/mcp', method: 'post' as const, handler: originalHandler }

    const result = buildPlugin(makeConfig([inputEndpoint]), makeOptions())
    const returned = (result.endpoints ?? []).find((e) => e.path === '/mcp')

    expect(returned).toBeDefined()
    expect(returned).not.toBe(inputEndpoint)
    expect(returned!.handler).not.toBe(originalHandler)
    expect(returned!.method).toBe('post')
  })

  it('passes non-MCP endpoints through by reference, unwrapped', () => {
    const otherHandler = async () => new Response('other')
    const other = { path: '/custom', method: 'get' as const, handler: otherHandler }
    const config = makeConfig([MCP_ENDPOINT, other])

    const result = buildPlugin(config, makeOptions())
    const returned = (result.endpoints ?? []).find((e) => e.path === '/custom')

    expect(returned).toBe(other)
    expect(returned!.handler).toBe(otherHandler)
  })

  it('does not mutate the incoming endpoints array', () => {
    const config = makeConfig()
    const before = [...(config.endpoints ?? [])]
    buildPlugin(config, makeOptions())
    expect(config.endpoints).toEqual(before)
  })

  it('is idempotent: building twice from the same config wraps once, not twice', () => {
    // The old in-place assignment stacked a wrapper on every build.
    const originalHandler = async () => new Response('ok')
    const inputEndpoint = { path: '/mcp', method: 'post' as const, handler: originalHandler }
    const config = makeConfig([inputEndpoint])

    const first = buildPlugin(config, makeOptions())
    const second = buildPlugin(config, makeOptions())

    const firstHandler = (first.endpoints ?? []).find((e) => e.path === '/mcp')!.handler
    const secondHandler = (second.endpoints ?? []).find((e) => e.path === '/mcp')!.handler
    // Each build wraps the SAME original handler, never a previous wrapper.
    expect(inputEndpoint.handler).toBe(originalHandler)
    expect(firstHandler).not.toBe(secondHandler)
  })

  it('still throws PLUGIN_ORDER when no /mcp endpoint is present', () => {
    expect(() => buildPlugin(makeConfig([]), makeOptions())).toThrow(PayloadMcpOAuthError)
  })
})

describe('buildPlugin — discovery advertises the operator scopes', () => {
  async function readMetadata(path: string, mcpPluginOptions: Record<string, unknown>) {
    const result = buildPlugin(makeConfig(), makeOptions({ mcpPluginOptions: mcpPluginOptions as never }))
    const endpoint = (result.endpoints ?? []).find((e) => e.path === path && e.method === 'get')
    expect(endpoint).toBeDefined()
    const res = (await endpoint!.handler({ method: 'GET' } as never)) as Response
    return (await res.json()) as Record<string, unknown>
  }

  it('lists the enabled scopes in the authorization-server metadata', async () => {
    const m = await readMetadata('/.well-known/oauth-authorization-server', {
      collections: { posts: { enabled: true } },
    })
    expect(m['scopes_supported']).toEqual(['posts:read', 'posts:write', 'posts:delete'])
    expect(m['authorization_response_iss_parameter_supported']).toBe(true)
  })

  it('lists the same scopes in the protected-resource metadata', async () => {
    const m = await readMetadata('/.well-known/oauth-protected-resource', {
      collections: { posts: { enabled: true } },
    })
    expect(m['scopes_supported']).toEqual(['posts:read', 'posts:write', 'posts:delete'])
  })

  it('omits scopes_supported when the operator enables nothing', async () => {
    const m = await readMetadata('/.well-known/oauth-authorization-server', {})
    expect(m).not.toHaveProperty('scopes_supported')
  })
})

describe('buildPlugin — detects a copied mcpPluginOptions (#51)', () => {
  /** Mimics what Payload's definePlugin produces: the ORIGINAL options on `.options`. */
  function fakeMcpPlugin(options: unknown) {
    const fn = ((config: unknown) => config) as ((c: unknown) => unknown) & {
      slug?: string
      options?: unknown
      order?: number
    }
    fn.slug = '@payloadcms/plugin-mcp'
    fn.options = options
    fn.order = 10
    return fn
  }

  function configWithMcpPlugin(pluginOptions: unknown) {
    return {
      ...makeConfig(),
      plugins: [fakeMcpPlugin(pluginOptions)],
    } as unknown as import('payload').Config
  }

  it('accepts the same object reference', () => {
    const shared = { collections: { posts: { enabled: true } } }
    expect(() =>
      buildPlugin(configWithMcpPlugin(shared), makeOptions({ mcpPluginOptions: shared as never })),
    ).not.toThrow()
  })

  it('throws when given a spread copy instead of the shared reference', () => {
    // The mistake this exists to catch: `overrideAuth` gets installed on an
    // object the MCP handler never reads, so OAuth tokens 401 while API keys
    // keep working — a symptom that looks like a token bug and is not.
    const shared = { collections: { posts: { enabled: true } } }
    expect(() =>
      buildPlugin(configWithMcpPlugin(shared), makeOptions({ mcpPluginOptions: { ...shared } as never })),
    ).toThrow(/same object you passed to mcpPlugin/)
  })

  it('reports the error with a MCP_OPTIONS_NOT_SHARED code', () => {
    const shared = { collections: {} }
    try {
      buildPlugin(configWithMcpPlugin(shared), makeOptions({ mcpPluginOptions: {} as never }))
      throw new Error('expected a throw')
    } catch (err) {
      expect(err).toBeInstanceOf(PayloadMcpOAuthError)
      expect((err as PayloadMcpOAuthError).code).toBe('MCP_OPTIONS_NOT_SHARED')
    }
  })

  it('stays silent when the config carries no plugins array', () => {
    // No evidence either way — guessing would break working setups.
    expect(() => buildPlugin(makeConfig(), makeOptions())).not.toThrow()
  })

  it('stays silent when the MCP plugin has no slug (older plugin-mcp)', () => {
    const unslugged = ((config: unknown) => config) as ((c: unknown) => unknown) & { options?: unknown }
    unslugged.options = { collections: {} }
    const config = { ...makeConfig(), plugins: [unslugged] } as unknown as import('payload').Config
    expect(() => buildPlugin(config, makeOptions())).not.toThrow()
  })

  it('stays silent when the MCP plugin exposes no options', () => {
    const noOptions = ((config: unknown) => config) as ((c: unknown) => unknown) & { slug?: string }
    noOptions.slug = '@payloadcms/plugin-mcp'
    const config = { ...makeConfig(), plugins: [noOptions] } as unknown as import('payload').Config
    expect(() => buildPlugin(config, makeOptions())).not.toThrow()
  })
})
