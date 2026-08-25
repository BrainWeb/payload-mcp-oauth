import { beforeEach, describe, expect, it, vi } from 'vitest'
import { issueTokenPair, rotateRefreshToken } from '../../../src/lib/tokens.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

function makePayload(overrides: Record<string, unknown> = {}) {
  return {
    create: vi.fn().mockResolvedValue({ id: 'token-doc-1' }),
    find: vi.fn().mockResolvedValue({ docs: [] }),
    // Bulk update (where) returns BulkOperationResult { docs, errors }
    update: vi.fn().mockResolvedValue({ docs: [{ id: 'token-doc-1' }] }),
    delete: vi.fn().mockResolvedValue({ docs: [] }),
    ...overrides,
  }
}

/** The row `isClientActive` finds for a client that is still switched on. */
const ACTIVE_CLIENT_DOC = { id: 'client-doc-1', clientId: 'client-1', isActive: true }

/**
 * `rotateRefreshToken` issues an `isClientActive` lookup BEFORE the token
 * lookup, so ordered `find` mocks must yield the client row first. Builds that
 * sequence: active client, then each supplied response in order.
 */
function findWithActiveClient(...responses: Array<{ docs: unknown[] }>) {
  const mock = vi.fn().mockResolvedValue({ docs: [] })
  mock.mockResolvedValueOnce({ docs: [ACTIVE_CLIENT_DOC] })
  for (const r of responses) mock.mockResolvedValueOnce(r)
  return mock
}

const BASE_PARAMS = {
  clientId: 'client-1',
  userId: 'user-1',
  scope: 'posts:read',
  capabilities: { posts: { find: true } },
}

describe('issueTokenPair', () => {
  it('creates two documents (access + refresh) and returns a token pair', async () => {
    const payload = makePayload()
    const pair = await issueTokenPair(payload as never, BASE_PARAMS)

    expect(payload.create).toHaveBeenCalledTimes(2)
    expect(pair.access_token).toMatch(/^pmoauth_at_/)
    expect(pair.refresh_token).toMatch(/^pmoauth_rt_/)
    expect(pair.token_type).toBe('Bearer')
    expect(pair.expires_in).toBe(3600) // default 60 min
    expect(pair.scope).toBe('posts:read')
  })

  it('stores hashes — not plaintext tokens', async () => {
    const payload = makePayload()
    const pair = await issueTokenPair(payload as never, BASE_PARAMS)

    const calls = payload.create.mock.calls as Array<[{ data: Record<string, unknown> }]>
    const hashes = calls.map((c) => c[0]?.data?.tokenHash as string)
    expect(hashes[0]).not.toBe(pair.access_token)
    expect(hashes[1]).not.toBe(pair.refresh_token)
    expect(hashes[0]).toHaveLength(64)
    expect(hashes[1]).toHaveLength(64)
  })

  it('respects custom TTL options', async () => {
    const payload = makePayload()
    const pair = await issueTokenPair(payload as never, {
      ...BASE_PARAMS,
      accessTtlSeconds: 300,
    })
    expect(pair.expires_in).toBe(300)
  })
})

describe('rotateRefreshToken', () => {
  const activeToken = {
    id: 'refresh-doc-1',
    tokenHash: '', // will be ignored in mock
    tokenType: 'refresh',
    clientId: 'client-1',
    userId: 'user-1',
    scope: 'posts:read',
    capabilities: { posts: { find: true } },
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    revokedAt: null,
  }

  it('returns a new token pair and atomically revokes the old refresh token', async () => {
    const payload = makePayload({
      find: findWithActiveClient({ docs: [activeToken] }),
    })
    const pair = await rotateRefreshToken(payload as never, 'pmoauth_rt_old', { clientId: 'client-1' })

    expect(pair).not.toBeNull()
    expect(pair?.access_token).toMatch(/^pmoauth_at_/)
    expect(pair?.refresh_token).toMatch(/^pmoauth_rt_/)
    // Atomic revocation uses where clause, not id
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.any(Object), data: expect.objectContaining({ revokedAt: expect.any(String) }) }),
    )
    expect(payload.update.mock.calls[0]?.[0]).not.toHaveProperty('id')
  })

  it('returns null for an unknown refresh token', async () => {
    const payload = makePayload({ find: findWithActiveClient({ docs: [] }) })
    expect(await rotateRefreshToken(payload as never, 'pmoauth_rt_unknown', { clientId: 'client-1' })).toBeNull()
  })

  it('returns null for an expired refresh token', async () => {
    const expired = { ...activeToken, expiresAt: new Date(Date.now() - 1000).toISOString() }
    const payload = makePayload({ find: findWithActiveClient({ docs: [expired] }) })
    expect(await rotateRefreshToken(payload as never, 'pmoauth_rt_exp', { clientId: 'client-1' })).toBeNull()
  })

  it('triggers family revocation on reuse of a consumed token', async () => {
    const consumed = { ...activeToken, revokedAt: new Date().toISOString() }
    // First find returns the consumed token; second find (revokeAllForClientUser) returns active tokens
    const payload = makePayload({
      find: findWithActiveClient({ docs: [consumed] }, { docs: [{ id: 'at-1' }, { id: 'at-2' }] }),
      // revokeAllForClientUser uses update-by-id (not bulk update), so the mock returns a plain doc
      update: vi.fn().mockResolvedValue({ id: 'some-token' }),
    })

    const result = await rotateRefreshToken(payload as never, 'pmoauth_rt_reused', { clientId: 'client-1' })
    expect(result).toBeNull()
    // Both active tokens should be revoked
    expect(payload.update).toHaveBeenCalledTimes(2)
  })

  it('returns null when atomic revocation loses the race (concurrent rotation)', async () => {
    // Both requests found the token valid, but the atomic WHERE-update returns 0 rows
    // because the other request already set revokedAt.
    const payload = makePayload({
      find: findWithActiveClient({ docs: [activeToken] }),
      update: vi.fn().mockResolvedValue({ docs: [] }),
    })
    expect(await rotateRefreshToken(payload as never, 'pmoauth_rt_race', { clientId: 'client-1' })).toBeNull()
  })

  it('refuses to rotate when the client has been deactivated', async () => {
    // isClientActive filters on isActive, so a deactivated client matches nothing.
    // The refresh token itself is still valid — deactivation alone must stop it.
    const payload = makePayload({ find: vi.fn().mockResolvedValue({ docs: [] }) })

    expect(
      await rotateRefreshToken(payload as never, 'pmoauth_rt_valid', { clientId: 'client-1' }),
    ).toBeNull()
    // Short-circuits before the token lookup, and mints nothing.
    expect(payload.find).toHaveBeenCalledTimes(1)
    expect(payload.create).not.toHaveBeenCalled()
  })

  it('fails closed when the client lookup throws', async () => {
    const payload = makePayload({ find: vi.fn().mockRejectedValue(new Error('db down')) })
    expect(
      await rotateRefreshToken(payload as never, 'pmoauth_rt_valid', { clientId: 'client-1' }),
    ).toBeNull()
    expect(payload.create).not.toHaveBeenCalled()
  })

  it('applies the caller-supplied TTLs to the rotated pair', async () => {
    const payload = makePayload({ find: findWithActiveClient({ docs: [activeToken] }) })
    const pair = await rotateRefreshToken(payload as never, 'pmoauth_rt_old', {
      clientId: 'client-1',
      accessTtlSeconds: 120,
      refreshTtlSeconds: 600,
    })
    expect(pair?.expires_in).toBe(120)
  })
})
