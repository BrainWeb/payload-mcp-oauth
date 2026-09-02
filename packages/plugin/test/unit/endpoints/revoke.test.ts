import { describe, expect, it, vi } from 'vitest'
import { makeRevokeHandler } from '../../../src/endpoints/revoke.js'
import { hashToken } from '../../../src/lib/token-storage.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

const VALID_TOKEN = 'pmoauth_at_Rv8xKq3mN2pLs9nW4tF2qMr6kB1uJ7pabc'
const VALID_REFRESH = 'pmoauth_rt_Rv8xKq3mN2pLs9nW4tF2qMr6kB1uJ7pabc'

function makeTokenDoc(overrides: Record<string, unknown> = {}) {
  return {
    id: 'tok-1',
    tokenHash: hashToken(VALID_TOKEN),
    tokenType: 'access',
    clientId: 'client-1',
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
      update: vi.fn().mockResolvedValue({}),
    },
  }
}

describe('makeRevokeHandler', () => {
  it('returns 200 and revokes a known token', async () => {
    const req = makeReq({ token: VALID_TOKEN, client_id: 'client-1' }, [makeTokenDoc()])
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
    expect(req.payload.update).toHaveBeenCalledOnce()
  })

  it('returns 200 for unknown token (idempotent per RFC 7009)', async () => {
    const req = makeReq({ token: 'pmoauth_at_unknown' }, [])
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
    expect(req.payload.update).not.toHaveBeenCalled()
  })

  it('returns 200 when token is already revoked', async () => {
    const req = makeReq({ token: VALID_TOKEN }, [makeTokenDoc({ revokedAt: new Date().toISOString() })])
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
    expect(req.payload.update).not.toHaveBeenCalled()
  })

  it('returns 200 without revoking if client_id does not match', async () => {
    const req = makeReq({ token: VALID_TOKEN, client_id: 'other-client' }, [makeTokenDoc()])
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
    expect(req.payload.update).not.toHaveBeenCalled()
  })

  it('revokes a refresh token with a single update, leaving the cascade to the collection hook', async () => {
    // Sibling access tokens are revoked by `cascadeRevokeAccessTokens` (an
    // afterChange hook on oauth-tokens) which this update fires. The endpoint
    // used to run a second cascade of its own over `parentTokenId`, but that
    // query could never match: issueTokenPair stamps both members of a pair with
    // the id of the refresh token they REPLACED, so a token's sibling never
    // carries its id. The old test only passed because it mocked `find` to
    // return access tokens on the second call.
    const refreshDoc = { id: 'refresh-1', tokenHash: hashToken(VALID_REFRESH), tokenType: 'refresh', clientId: 'client-1', revokedAt: null }
    const req = makeReq({ token: VALID_REFRESH, client_id: 'client-1' }, [refreshDoc])
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
    expect(req.payload.update).toHaveBeenCalledTimes(1)
    expect(req.payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'oauth-tokens', id: 'refresh-1' }),
    )
  })

  it('returns 200 with no token in body', async () => {
    const req = makeReq({})
    const res = await makeRevokeHandler()(req as never)
    expect(res.status).toBe(200)
  })
})
