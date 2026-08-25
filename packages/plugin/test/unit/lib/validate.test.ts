import { describe, expect, it, vi } from 'vitest'
import { validateAccessToken } from '../../../src/lib/validate.js'
import { hashToken } from '../../../src/lib/token-storage.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

function makePayload(overrides: Record<string, unknown> = {}) {
  return {
    find: vi.fn().mockResolvedValue({ docs: [] }),
    update: vi.fn().mockResolvedValue({}),
    ...overrides,
  }
}

const VALID_TOKEN = 'pmoauth_at_Rv8xKq3mN2pLs9nW4tF2qMr6kB1uJ7p_ab'

function makeTokenDoc(overrides: Record<string, unknown> = {}) {
  return {
    id: 'tok-1',
    tokenHash: hashToken(VALID_TOKEN),
    tokenType: 'access',
    clientId: 'client-1',
    userId: 'user-1',
    scope: 'posts:read',
    capabilities: { posts: { find: true } },
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    revokedAt: null,
    ...overrides,
  }
}

/** The row `isClientActive` finds for a client that is still switched on. */
const ACTIVE_CLIENT_DOC = { id: 'client-doc-1', clientId: 'client-1', isActive: true }

/**
 * `validateAccessToken` issues two lookups in order: the token, then the client
 * (to honour `isActive`). A single `mockResolvedValue` would answer both with
 * the token row and pass for the wrong reason, so model the real sequence.
 */
function findTokenThenActiveClient(tokenDoc: unknown) {
  return vi
    .fn()
    .mockResolvedValueOnce({ docs: [tokenDoc] })
    .mockResolvedValueOnce({ docs: [ACTIVE_CLIENT_DOC] })
}

describe('validateAccessToken', () => {
  it('returns TokenContext for a valid token', async () => {
    const payload = makePayload({
      find: findTokenThenActiveClient(makeTokenDoc()),
    })

    const ctx = await validateAccessToken(payload as never, VALID_TOKEN)

    expect(ctx).not.toBeNull()
    expect(ctx?.userId).toBe('user-1')
    expect(ctx?.clientId).toBe('client-1')
    expect(ctx?.scope).toBe('posts:read')
    expect(ctx?.capabilities).toEqual({ posts: { find: true } })
  })

  it('returns null for a token not starting with pmoauth_at_', async () => {
    const payload = makePayload()
    expect(await validateAccessToken(payload as never, 'pmoauth_rt_somerefresh')).toBeNull()
    expect(await validateAccessToken(payload as never, 'some-api-key')).toBeNull()
    expect(payload.find).not.toHaveBeenCalled()
  })

  it('returns null when the token hash is not found', async () => {
    const payload = makePayload()
    expect(await validateAccessToken(payload as never, VALID_TOKEN)).toBeNull()
  })

  it('returns null for a revoked token', async () => {
    const payload = makePayload({
      find: vi.fn().mockResolvedValue({
        docs: [makeTokenDoc({ revokedAt: new Date().toISOString() })],
      }),
    })
    expect(await validateAccessToken(payload as never, VALID_TOKEN)).toBeNull()
  })

  it('returns null for an expired token (beyond clock skew)', async () => {
    const payload = makePayload({
      find: vi.fn().mockResolvedValue({
        docs: [makeTokenDoc({ expiresAt: new Date(Date.now() - 31_000).toISOString() })],
      }),
    })
    expect(await validateAccessToken(payload as never, VALID_TOKEN)).toBeNull()
  })

  it('accepts a token within the 30-second clock skew window', async () => {
    const payload = makePayload({
      find: vi.fn().mockResolvedValue({
        docs: [makeTokenDoc({ expiresAt: new Date(Date.now() - 10_000).toISOString() })],
      }),
    })
    expect(await validateAccessToken(payload as never, VALID_TOKEN)).not.toBeNull()
  })

  it('fires a best-effort lastUsedAt update without awaiting', async () => {
    const updateFn = vi.fn().mockResolvedValue({})
    const payload = makePayload({
      find: vi.fn().mockResolvedValue({ docs: [makeTokenDoc()] }),
      update: updateFn,
    })

    await validateAccessToken(payload as never, VALID_TOKEN)
    // Give the microtask queue a tick to process the fire-and-forget update
    await Promise.resolve()
    expect(updateFn).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ lastUsedAt: expect.any(String) }) }),
    )
  })

  it('does not throw when the lastUsedAt update fails', async () => {
    const payload = makePayload({
      find: vi.fn().mockResolvedValue({ docs: [makeTokenDoc()] }),
      update: vi.fn().mockRejectedValue(new Error('DB error')),
    })
    await expect(validateAccessToken(payload as never, VALID_TOKEN)).resolves.not.toBeNull()
  })

  it('rejects a live token whose client has been deactivated', async () => {
    // Token itself is valid and unrevoked; only the client was switched off.
    // Deactivating in the admin UI must cut access off on the next request
    // rather than waiting out the token's remaining lifetime.
    const payload = makePayload({
      find: vi
        .fn()
        .mockResolvedValueOnce({ docs: [makeTokenDoc()] })
        .mockResolvedValueOnce({ docs: [] }),
    })

    expect(await validateAccessToken(payload as never, VALID_TOKEN)).toBeNull()
    // No lastUsedAt write for a rejected token.
    expect(payload.update).not.toHaveBeenCalled()
  })

  it('fails closed when the client lookup throws', async () => {
    const payload = makePayload({
      find: vi
        .fn()
        .mockResolvedValueOnce({ docs: [makeTokenDoc()] })
        .mockRejectedValueOnce(new Error('db down')),
    })

    expect(await validateAccessToken(payload as never, VALID_TOKEN)).toBeNull()
  })
})
