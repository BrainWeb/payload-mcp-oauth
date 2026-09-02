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
