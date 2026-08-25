import type { Payload } from 'payload'
import { isClientActive } from './clients.js'
import { generateToken } from './token-generation.js'
import { hashToken } from './token-storage.js'

export interface IssueTokenPairParams {
  clientId: string
  userId: string
  scope: string
  capabilities: Record<string, unknown>
  accessTtlSeconds?: number
  refreshTtlSeconds?: number
  parentTokenId?: string
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  expires_in: number
  token_type: 'Bearer'
  scope: string
}

// Fallbacks for direct callers only — the token endpoint always passes the
// operator-resolved values from `PayloadMcpOAuthConfig`. These MUST stay equal
// to the documented defaults on `accessTokenTtlSeconds` / `refreshTokenTtlSeconds`:
// the refresh fallback used to be 30 days against a documented 1 day, so every
// deployment issued refresh tokens with 30x the advertised lifetime.
const DEFAULT_ACCESS_TTL = 3600  // 1 hour
const DEFAULT_REFRESH_TTL = 86400 // 1 day

export async function issueTokenPair(payload: Payload, params: IssueTokenPairParams): Promise<TokenPair> {
  const {
    clientId,
    userId,
    scope,
    capabilities,
    accessTtlSeconds = DEFAULT_ACCESS_TTL,
    refreshTtlSeconds = DEFAULT_REFRESH_TTL,
    parentTokenId,
  } = params

  const accessPlaintext = generateToken('access')
  const refreshPlaintext = generateToken('refresh')

  const now = Date.now()
  const accessExpiresAt = new Date(now + accessTtlSeconds * 1000).toISOString()
  const refreshExpiresAt = new Date(now + refreshTtlSeconds * 1000).toISOString()

  await payload.create({
    collection: 'oauth-tokens',
    overrideAccess: true,
    data: {
      tokenHash: hashToken(accessPlaintext),
      tokenType: 'access',
      clientId,
      userId,
      scope,
      capabilities,
      expiresAt: accessExpiresAt,
      parentTokenId: parentTokenId ?? null,
    },
  })

  await payload.create({
    collection: 'oauth-tokens',
    overrideAccess: true,
    data: {
      tokenHash: hashToken(refreshPlaintext),
      tokenType: 'refresh',
      clientId,
      userId,
      scope,
      capabilities,
      expiresAt: refreshExpiresAt,
      parentTokenId: parentTokenId ?? null,
    },
  })

  return {
    access_token: accessPlaintext,
    refresh_token: refreshPlaintext,
    expires_in: accessTtlSeconds,
    token_type: 'Bearer',
    scope,
  }
}

export async function rotateRefreshToken(
  payload: Payload,
  refreshPlaintext: string,
  params: { clientId: string; accessTtlSeconds?: number; refreshTtlSeconds?: number },
): Promise<TokenPair | null> {
  // A deactivated client must not be able to mint a fresh token family from a
  // refresh token it already holds — otherwise "deactivate" only delays access
  // by one refresh interval instead of ending it.
  if (!(await isClientActive(payload, params.clientId))) return null

  const tokenHash = hashToken(refreshPlaintext)

  const { docs } = await payload.find({
    collection: 'oauth-tokens',
    overrideAccess: true,
    where: {
      and: [
        { tokenHash: { equals: tokenHash } },
        { tokenType: { equals: 'refresh' } },
        { clientId: { equals: params.clientId } },
      ],
    },
    limit: 1,
    pagination: false,
  })

  const token = docs[0]
  if (!token) return null

  // Reject if expired
  if (new Date(token['expiresAt'] as string) < new Date()) return null

  // Reuse detection: token already revoked means it was used after rotation
  if (token['revokedAt']) {
    // Revoke all active tokens for this client+user (entire family is compromised)
    await revokeAllForClientUser(payload, token['clientId'] as string, token['userId'] as string)
    return null
  }

  // Atomic conditional revocation — only one concurrent request can win.
  // Two simultaneous requests with the same refresh token will both find the
  // token above (not yet revoked), but only one can satisfy the
  // UPDATE WHERE revokedAt IS NULL constraint. The loser gets back an empty
  // docs array and returns null without issuing a second token family.
  const result = await payload.update({
    collection: 'oauth-tokens',
    overrideAccess: true,
    where: {
      and: [
        { tokenHash: { equals: tokenHash } },
        { revokedAt: { equals: null } },
      ],
    },
    data: { revokedAt: new Date().toISOString() },
  })

  const revoked = (result as unknown as { docs: unknown[] }).docs
  if (!revoked?.length) return null

  // Issue fresh pair, linking parentTokenId for chain traceability
  return issueTokenPair(payload, {
    clientId: token['clientId'] as string,
    userId: token['userId'] as string,
    scope: (token['scope'] as string | null | undefined) ?? '',
    capabilities: (token['capabilities'] as Record<string, unknown> | null | undefined) ?? {},
    accessTtlSeconds: params.accessTtlSeconds,
    refreshTtlSeconds: params.refreshTtlSeconds,
    parentTokenId: String(token.id),
  })
}

async function revokeAllForClientUser(payload: Payload, clientId: string, userId: string): Promise<void> {
  const { docs } = await payload.find({
    collection: 'oauth-tokens',
    overrideAccess: true,
    where: {
      and: [
        { clientId: { equals: clientId } },
        { userId: { equals: userId } },
        { revokedAt: { equals: null } },
      ],
    },
    limit: 1000,
    pagination: false,
  })

  const revokedAt = new Date().toISOString()
  await Promise.all(
    docs.map((t) =>
      payload.update({
        collection: 'oauth-tokens',
        overrideAccess: true,
        id: t.id,
        data: { revokedAt },
      }),
    ),
  )
}
