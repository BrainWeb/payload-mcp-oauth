import { describe, expect, it, vi } from 'vitest'
import { oauthTokensCollection } from '../../../src/collections/tokens.js'

describe('oauthTokensCollection', () => {
  it('has the correct slug', () => {
    expect(oauthTokensCollection.slug).toBe('oauth-tokens')
  })

  it('has all required fields', () => {
    const fieldNames = oauthTokensCollection.fields
      .filter((f): f is Extract<typeof f, { name: string }> => 'name' in f)
      .map((f) => f.name)

    expect(fieldNames).toContain('tokenHash')
    expect(fieldNames).toContain('tokenType')
    expect(fieldNames).toContain('clientId')
    expect(fieldNames).toContain('userId')
    expect(fieldNames).toContain('scope')
    expect(fieldNames).toContain('capabilities')
    expect(fieldNames).toContain('expiresAt')
    expect(fieldNames).toContain('revokedAt')
    expect(fieldNames).toContain('lastUsedAt')
    expect(fieldNames).toContain('parentTokenId')
  })

  it('marks tokenHash as required, unique, and indexed', () => {
    const field = oauthTokensCollection.fields.find(
      (f): f is Extract<typeof f, { name: string }> => 'name' in f && f.name === 'tokenHash',
    )
    expect(field?.required).toBe(true)
    expect(field?.unique).toBe(true)
    expect(field?.index).toBe(true)
  })

  it('marks lookup fields as indexed', () => {
    const indexedFields = ['tokenType', 'clientId', 'userId', 'expiresAt', 'revokedAt', 'parentTokenId']
    indexedFields.forEach((name) => {
      const field = oauthTokensCollection.fields.find(
        (f): f is Extract<typeof f, { name: string }> => 'name' in f && f.name === name,
      )
      expect(field?.index, `${name} should be indexed`).toBe(true)
    })
  })

  it('tokenType only allows access and refresh', () => {
    const field = oauthTokensCollection.fields.find(
      (f): f is Extract<typeof f, { name: string }> => 'name' in f && f.name === 'tokenType',
    ) as { options?: Array<{ value: string }> } | undefined
    const values = field?.options?.map((o) => o.value)
    expect(values).toEqual(['access', 'refresh'])
  })

  it('stores capabilities as json', () => {
    const field = oauthTokensCollection.fields.find(
      (f): f is Extract<typeof f, { name: string; type: string }> =>
        'name' in f && f.name === 'capabilities',
    )
    expect(field?.type).toBe('json')
  })

  it('has a cascade revocation afterChange hook', () => {
    expect(oauthTokensCollection.hooks?.afterChange?.length).toBeGreaterThan(0)
  })

  it('has access control functions', () => {
    expect(typeof oauthTokensCollection.access?.read).toBe('function')
    expect(typeof oauthTokensCollection.access?.update).toBe('function')
  })

  it('denies ALL public REST/GraphQL access, even to authenticated users (server-managed only)', () => {
    const access = oauthTokensCollection.access
    const ctx = { req: { user: { id: '1', collection: 'users' } } } as never
    for (const op of ['create', 'read', 'update', 'delete'] as const) {
      const fn = access?.[op]
      if (typeof fn !== 'function') throw new Error(`${op} must be a function`)
      expect(fn(ctx), `${op} must be denied`).toBe(false)
    }
  })

  it('has timestamps disabled', () => {
    expect(oauthTokensCollection.timestamps).toBe(false)
  })
})

describe('oauthTokensCollection — cascadeRevokeAccessTokens', () => {
  /** Runs the named afterChange hook against a fake req. */
  async function runCascade(args: Record<string, unknown>, activeAccessTokens: unknown[] = []) {
    const update = vi.fn().mockResolvedValue({})
    const req = {
      payload: {
        find: vi.fn().mockResolvedValue({ docs: activeAccessTokens }),
        update,
      },
    }
    const hooks = oauthTokensCollection.hooks?.afterChange ?? []
    for (const hook of hooks) {
      await (hook as (a: unknown) => unknown)({ req, ...args })
    }
    return { update, find: req.payload.find }
  }

  const refreshDoc = {
    id: 'refresh-1',
    tokenType: 'refresh',
    clientId: 'client-1',
    userId: 'user-1',
    revokedAt: '2026-01-01T00:00:00.000Z',
  }

  it('revokes the client+user active access tokens when a refresh token is revoked', async () => {
    // This is the cascade the revoke endpoint relies on, so it needs its own
    // coverage rather than being asserted indirectly through a mocked find.
    const { update, find } = await runCascade(
      { doc: refreshDoc, previousDoc: { ...refreshDoc, revokedAt: null }, operation: 'update' },
      [{ id: 'access-1' }, { id: 'access-2' }],
    )
    expect(find).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'oauth-tokens' }),
    )
    const revoked = update.mock.calls
      .filter((c) => (c[0] as { data?: { revokedAt?: string } }).data?.revokedAt)
      .map((c) => (c[0] as { id: string }).id)
    expect(revoked).toEqual(['access-1', 'access-2'])
  })

  it('does nothing when revokedAt was already set', async () => {
    const { update } = await runCascade(
      { doc: refreshDoc, previousDoc: refreshDoc, operation: 'update' },
      [{ id: 'access-1' }],
    )
    expect(update).not.toHaveBeenCalled()
  })

  it('does nothing for an access token', async () => {
    const { update } = await runCascade(
      {
        doc: { ...refreshDoc, tokenType: 'access' },
        previousDoc: { ...refreshDoc, tokenType: 'access', revokedAt: null },
        operation: 'update',
      },
      [{ id: 'access-1' }],
    )
    expect(update).not.toHaveBeenCalled()
  })
})
