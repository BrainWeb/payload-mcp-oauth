import { describe, expect, it } from 'vitest'
import {
  toCamelCase,
  buildFullCapabilities,
  intersectCapabilities,
  scopeToCapabilities,
} from '../../../src/lib/scope.js'
import type { ScopeResult } from '../../../src/lib/scope.js'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'

const MCP_OPTIONS: MCPPluginConfig = {
  collections: {
    posts: { enabled: true },
    media: { enabled: { find: true, create: true } as never },
    'read-only': { enabled: { find: true } as never },
    'blog-posts': { enabled: true },
  },
  globals: {
    settings: { enabled: true },
    'site-config': { enabled: { find: true } as never },
  },
}

/** Narrows a ScopeResult to its granted capabilities, failing loudly on any other kind. */
function caps(r: ScopeResult): Record<string, unknown> {
  if (r.kind !== 'scoped') throw new Error(`expected kind "scoped", got "${r.kind}"`)
  return r.capabilities
}

/** Narrows a ScopeResult to its rejected scope tokens. */
function invalid(r: ScopeResult): string[] {
  if (r.kind !== 'invalid') throw new Error(`expected kind "invalid", got "${r.kind}"`)
  return r.invalidScopes
}

describe('toCamelCase', () => {
  it('leaves simple slugs unchanged', () => {
    expect(toCamelCase('posts')).toBe('posts')
  })

  it('converts hyphenated slugs to camelCase', () => {
    expect(toCamelCase('blog-posts')).toBe('blogPosts')
    expect(toCamelCase('site-config')).toBe('siteConfig')
  })
})

describe('buildFullCapabilities', () => {
  it('grants full ops for collections with enabled: true', () => {
    const caps = buildFullCapabilities(MCP_OPTIONS)
    expect(caps['posts']).toEqual({ find: true, create: true, update: true, delete: true })
  })

  it('spreads partial object capabilities for collections', () => {
    const caps = buildFullCapabilities(MCP_OPTIONS)
    expect(caps['media']).toEqual({ find: true, create: true })
  })

  it('grants full ops for globals with enabled: true', () => {
    const caps = buildFullCapabilities(MCP_OPTIONS)
    expect(caps['settings']).toEqual({ find: true, update: true })
  })

  it('uses camelCase key for hyphenated slugs', () => {
    const caps = buildFullCapabilities(MCP_OPTIONS)
    expect(caps['blogPosts']).toEqual({ find: true, create: true, update: true, delete: true })
  })

  it('ignores nullish or missing entries', () => {
    const caps = buildFullCapabilities({ collections: { absent: null as never } })
    expect(caps['absent']).toBeUndefined()
  })
})

describe('scopeToCapabilities — empty scope', () => {
  it('returns kind "full" for an empty string — never an empty capability set', () => {
    // Regression guard for #75: an omitted scope means RFC 6749 §3.3's
    // pre-defined default (the full operator grant), NOT zero capabilities.
    // The two used to be indistinguishable, which is how issuance and
    // overrideAuth ended up disagreeing about what an empty scope meant.
    expect(scopeToCapabilities('', MCP_OPTIONS)).toEqual({ kind: 'full' })
  })

  it('returns kind "full" for a whitespace-only scope', () => {
    expect(scopeToCapabilities('   ', MCP_OPTIONS)).toEqual({ kind: 'full' })
  })

  it('distinguishes "full" from "invalid" — the two former {} cases', () => {
    expect(scopeToCapabilities('', MCP_OPTIONS).kind).toBe('full')
    expect(scopeToCapabilities('nope:read', MCP_OPTIONS).kind).toBe('invalid')
  })
})

describe('scopeToCapabilities — collection scopes', () => {
  it('maps <slug>:read → { find: true }', () => {
    const r = scopeToCapabilities('posts:read', MCP_OPTIONS)
    expect(caps(r)['posts']).toEqual({ find: true })
  })

  it('maps <slug>:write → { create: true, update: true }', () => {
    const r = scopeToCapabilities('posts:write', MCP_OPTIONS)
    expect(caps(r)['posts']).toEqual({ create: true, update: true })
  })

  it('maps <slug>:delete → { delete: true }', () => {
    const r = scopeToCapabilities('posts:delete', MCP_OPTIONS)
    expect(caps(r)['posts']).toEqual({ delete: true })
  })

  it('rejects write when any required op is not enabled (no partial widening)', () => {
    // media has find+create only; write needs create+update — update not enabled
    const r = scopeToCapabilities('media:write', MCP_OPTIONS)
    expect(invalid(r)).toContain('media:write')
  })

  it('accepts write when all required ops are enabled', () => {
    // posts has all ops enabled
    const r = scopeToCapabilities('posts:write', MCP_OPTIONS)
    expect(r.kind).toBe('scoped')
  })

  it('rejects write for a read-only collection (no create/update)', () => {
    const r = scopeToCapabilities('read-only:write', MCP_OPTIONS)
    expect(r.kind).toBe('invalid')
  })

  it('converts hyphenated slug to camelCase key', () => {
    const r = scopeToCapabilities('blog-posts:read', MCP_OPTIONS)
    expect(caps(r)['blogPosts']).toEqual({ find: true })
  })
})

describe('scopeToCapabilities — global scopes', () => {
  it('maps global <slug>:read → { find: true }', () => {
    const r = scopeToCapabilities('settings:read', MCP_OPTIONS)
    expect(caps(r)['settings']).toEqual({ find: true })
  })

  it('maps global <slug>:write → { update: true }', () => {
    const r = scopeToCapabilities('settings:write', MCP_OPTIONS)
    expect(caps(r)['settings']).toEqual({ update: true })
  })

  it('rejects delete for globals (no delete operation)', () => {
    const r = scopeToCapabilities('settings:delete', MCP_OPTIONS)
    expect(r.kind).toBe('invalid')
    expect(invalid(r)).toContain('settings:delete')
  })

  it('rejects when op is not enabled for a partial global', () => {
    // site-config has only find enabled; write needs update which is not enabled
    const r = scopeToCapabilities('site-config:write', MCP_OPTIONS)
    expect(r.kind).toBe('invalid')
  })
})

describe('scopeToCapabilities — multi-token scopes', () => {
  it('combines capabilities across multiple tokens for the same slug', () => {
    const r = scopeToCapabilities('posts:read posts:delete', MCP_OPTIONS)
    expect(caps(r)['posts']).toEqual({ find: true, delete: true })
  })

  it('combines capabilities across different slugs', () => {
    const r = scopeToCapabilities('posts:read settings:write', MCP_OPTIONS)
    expect(caps(r)['posts']).toEqual({ find: true })
    expect(caps(r)['settings']).toEqual({ update: true })
  })

  it('fails the entire result when any token is invalid', () => {
    const r = scopeToCapabilities('posts:read unknown:read', MCP_OPTIONS)
    // No partial capabilities leaked — the entire grant is rejected, and the
    // "invalid" kind can no longer be mistaken for the full-grant "full" kind.
    expect(invalid(r)).toContain('unknown:read')
  })
})

describe('scopeToCapabilities — invalid tokens', () => {
  it('rejects tokens without a colon separator', () => {
    expect(scopeToCapabilities('openid', MCP_OPTIONS).kind).toBe('invalid')
    expect(scopeToCapabilities('mcp', MCP_OPTIONS).kind).toBe('invalid')
  })

  it('rejects tokens with a trailing colon (empty operation)', () => {
    expect(scopeToCapabilities('posts:', MCP_OPTIONS).kind).toBe('invalid')
  })

  it('rejects tokens with a leading colon (empty slug)', () => {
    expect(scopeToCapabilities(':read', MCP_OPTIONS).kind).toBe('invalid')
  })

  it('rejects an unknown collection slug', () => {
    expect(scopeToCapabilities('nonexistent:read', MCP_OPTIONS).kind).toBe('invalid')
  })

  it('rejects an unknown operation', () => {
    expect(scopeToCapabilities('posts:list', MCP_OPTIONS).kind).toBe('invalid')
    expect(scopeToCapabilities('posts:admin', MCP_OPTIONS).kind).toBe('invalid')
  })

  it('never widens: a single invalid token nullifies the whole grant', () => {
    const r = scopeToCapabilities('posts:read evil:all', MCP_OPTIONS)
    expect(r.kind).toBe('invalid')
    // The result carries no capabilities field at all, so no caller can read a
    // partial grant out of it — nor mistake it for the full grant.
    expect(r).not.toHaveProperty('capabilities')
  })
})

describe('intersectCapabilities', () => {
  it('keeps only operations enabled on BOTH sides', () => {
    const stored = { posts: { find: true, delete: true } }
    const allowed = { posts: { find: true, create: true } }
    expect(intersectCapabilities(stored, allowed)).toEqual({ posts: { find: true } })
  })

  it('drops a capability the operator has since disabled entirely', () => {
    // The privilege-retention case: a token issued while `posts` was enabled
    // must not keep acting on it after the operator turns the collection off.
    const stored = { posts: { find: true }, media: { find: true } }
    const allowed = { media: { find: true } }
    expect(intersectCapabilities(stored, allowed)).toEqual({ media: { find: true } })
  })

  it('drops an operation the operator has since disabled', () => {
    const stored = { posts: { delete: true } }
    const allowed = { posts: { find: true, create: true, update: true } }
    expect(intersectCapabilities(stored, allowed)).toEqual({})
  })

  it('treats an explicitly false live operation as disabled', () => {
    const stored = { posts: { delete: true } }
    const allowed = { posts: { find: true, delete: false } }
    expect(intersectCapabilities(stored, allowed)).toEqual({})
  })

  it('never widens: an operation absent from the stored grant is not added back', () => {
    const stored = { posts: { find: true } }
    const allowed = { posts: { find: true, create: true, update: true, delete: true } }
    expect(intersectCapabilities(stored, allowed)).toEqual({ posts: { find: true } })
  })

  it('omits keys reduced to nothing rather than leaving empty objects', () => {
    const stored = { posts: { delete: true }, media: { find: true } }
    const allowed = { posts: { find: true }, media: { find: true } }
    expect(intersectCapabilities(stored, allowed)).toEqual({ media: { find: true } })
  })

  it('is a no-op when the live config still allows everything stored', () => {
    const stored = { posts: { find: true, create: true } }
    expect(intersectCapabilities(stored, buildFullCapabilities(MCP_OPTIONS))).toEqual(stored)
  })

  it('ignores non-object entries on either side without throwing', () => {
    expect(intersectCapabilities({ posts: 'nonsense' }, { posts: { find: true } })).toEqual({})
    expect(intersectCapabilities({ posts: { find: true } }, { posts: null })).toEqual({})
    expect(intersectCapabilities({ posts: { find: true } }, {})).toEqual({})
  })

  it('drops prototype-chain keys rather than assigning them onto the result', () => {
    // `stored` is JSON read back from the database, so a key like __proto__ must
    // never be used as an index — assigning it would corrupt the returned
    // MCPAccessSettings object instead of adding a permission.
    const stored = JSON.parse('{"__proto__": {"find": true}, "posts": {"find": true}}') as Record<string, unknown>
    const allowed = JSON.parse('{"__proto__": {"find": true}, "posts": {"find": true}}') as Record<string, unknown>
    const result = intersectCapabilities(stored, allowed)
    expect(result).toEqual({ posts: { find: true } })
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype)
    expect(({} as Record<string, unknown>)['find']).toBeUndefined()
  })

  it('drops prototype-chain operation names too', () => {
    const stored = { posts: JSON.parse('{"constructor": true, "find": true}') as Record<string, unknown> }
    const allowed = { posts: JSON.parse('{"constructor": true, "find": true}') as Record<string, unknown> }
    expect(intersectCapabilities(stored, allowed)).toEqual({ posts: { find: true } })
  })

  it('does not treat an inherited key on the live config as an allowance', () => {
    const stored = { toString: { find: true } }
    expect(intersectCapabilities(stored, { posts: { find: true } })).toEqual({})
  })

  it('round-trips a full grant through the live ceiling unchanged', () => {
    const full = buildFullCapabilities(MCP_OPTIONS)
    expect(intersectCapabilities(full, full)).toEqual(full)
  })
})
