import type { Payload } from 'payload'
import { isClientActive } from './clients.js'
import { hashToken } from './token-storage.js'

export interface TokenContext {
  tokenId: string
  userId: string
  clientId: string
  scope: string
  capabilities: Record<string, unknown>
}

const CLOCK_SKEW_MS = 30_000

export async function validateAccessToken(
  payload: Payload,
  plaintext: string,
): Promise<TokenContext | null> {
  if (!plaintext.startsWith('pmoauth_at_')) return null

  const tokenHash = hashToken(plaintext)

  const { docs } = await payload.find({
    collection: 'oauth-tokens',
    overrideAccess: true,
    where: {
      and: [
        { tokenHash: { equals: tokenHash } },
        { tokenType: { equals: 'access' } },
      ],
    },
    limit: 1,
    pagination: false,
  })

  const token = docs[0]
  if (!token) return null
  if (token['revokedAt']) return null
  if (new Date(token['expiresAt'] as string).getTime() + CLOCK_SKEW_MS < Date.now()) return null

  // Deactivating a client in the admin UI must cut off its live credentials, not
  // just block new authorization flows. Checked here so an operator revoking a
  // connection takes effect on the very next MCP request.
  if (!(await isClientActive(payload, token['clientId'] as string))) return null

  // Best-effort non-blocking lastUsedAt update — never let this delay the response
  payload
    .update({
      collection: 'oauth-tokens',
      overrideAccess: true,
      id: token.id,
      data: { lastUsedAt: new Date().toISOString() },
    })
    .catch(() => undefined)

  return {
    tokenId: String(token.id),
    userId: token['userId'] as string,
    clientId: token['clientId'] as string,
    scope: (token['scope'] as string | null | undefined) ?? '',
    capabilities: (token['capabilities'] as Record<string, unknown> | null | undefined) ?? {},
  }
}
