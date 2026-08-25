import type { Access, CollectionAfterChangeHook, CollectionConfig } from 'payload'

// `create` is never a legitimate external operation: tokens are minted by the
// token endpoint (which uses `overrideAccess`). Deny it outright. `read`,
// `update`, and `delete` are gated to admins in plugin.ts via the resolved
// `adminAccess` rule — previously these were `() => false`, which also locked
// out the admin panel, so the management screen was unreachable.
const denyPublicAccess: Access = () => false

const cascadeRevokeAccessTokens: CollectionAfterChangeHook = async ({
  doc,
  previousDoc,
  operation,
  req,
}) => {
  if (operation !== 'update') return
  // Only cascade when revokedAt is newly set on a refresh token
  if (!doc.revokedAt || previousDoc?.revokedAt) return
  if (doc.tokenType !== 'refresh') return

  const { docs: activeAccessTokens } = await req.payload.find({
    collection: 'oauth-tokens',
    where: {
      and: [
        { clientId: { equals: doc.clientId as string } },
        { userId: { equals: doc.userId as string } },
        { tokenType: { equals: 'access' } },
        { revokedAt: { equals: null } },
      ],
    },
    limit: 1000,
    pagination: false,
    req,
  })

  await Promise.all(
    activeAccessTokens.map((token) =>
      req.payload.update({
        collection: 'oauth-tokens',
        id: token.id,
        data: { revokedAt: new Date().toISOString() },
        req,
      }),
    ),
  )
}

// How long an expired token row is kept before the sweep removes it. Expired
// rows are useless for authentication (validateAccessToken rejects them on
// expiry) but are worth retaining briefly so an operator can see recent activity
// in the admin UI. Revoked rows are covered by the same rule: revocation does
// not clear expiresAt, so a revoked token is swept once its own expiry is this
// far in the past.
const EXPIRED_TOKEN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

// Without this, `oauth-tokens` grew without bound: every refresh rotation writes
// two new rows and nothing ever removed the superseded ones, so a long-lived
// connection accumulated rows forever. Mirrors the sweep already run by
// `oauth-auth-codes` / `oauth-csrf-nonces`, using a single bulk delete rather
// than find + N deletes.
const sweepExpiredTokens: CollectionAfterChangeHook = async ({ operation, req }) => {
  if (operation !== 'create') return

  try {
    const cutoff = new Date(Date.now() - EXPIRED_TOKEN_RETENTION_MS).toISOString()
    await req.payload.delete({
      collection: 'oauth-tokens',
      overrideAccess: true,
      where: { expiresAt: { less_than: cutoff } },
      req,
    })
  } catch {
    // Best-effort housekeeping; never block token issuance on it.
  }
}

export const oauthTokensCollection: CollectionConfig = {
  slug: 'oauth-tokens',
  // Server-managed — opt out of document-locking so no FK column is added to
  // payload_locked_documents_rels (avoids the SQLite push rebuild bug; see clients.ts).
  lockDocuments: false,
  admin: {
    group: 'MCP',
    useAsTitle: 'clientId',
    defaultColumns: ['clientId', 'tokenType', 'scope', 'expiresAt', 'revokedAt'],
    description:
      'Access and refresh tokens issued via OAuth. Set "revoked at" (or delete a row) to revoke a connection. Read-only otherwise.',
  },
  access: {
    create: denyPublicAccess,
    read: denyPublicAccess,
    update: denyPublicAccess,
    delete: denyPublicAccess,
  },
  timestamps: false,
  hooks: {
    afterChange: [cascadeRevokeAccessTokens, sweepExpiredTokens],
  },
  fields: [
    {
      name: 'tokenHash',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      admin: {
        readOnly: true,
        hidden: true,
        description: 'HMAC-SHA-256 hash of the token plaintext. Never store plaintext.',
      },
    },
    {
      name: 'tokenType',
      type: 'select',
      required: true,
      index: true,
      admin: { readOnly: true },
      options: [
        { label: 'Access Token', value: 'access' },
        { label: 'Refresh Token', value: 'refresh' },
      ],
    },
    {
      name: 'clientId',
      type: 'text',
      required: true,
      index: true,
      admin: { readOnly: true },
    },
    {
      name: 'userId',
      type: 'text',
      required: true,
      index: true,
      admin: { readOnly: true },
    },
    {
      name: 'scope',
      type: 'text',
      admin: { readOnly: true },
    },
    {
      // Stores the MCPAccessSettings shape (minus user) so we can reconstruct
      // the full access settings at token validation time without a user lookup.
      name: 'capabilities',
      type: 'json',
      admin: {
        readOnly: true,
        description: 'MCPAccessSettings-compatible capability flags granted at consent.',
      },
    },
    {
      name: 'expiresAt',
      type: 'date',
      required: true,
      index: true,
      admin: { readOnly: true },
    },
    {
      name: 'revokedAt',
      type: 'date',
      index: true,
      admin: {
        readOnly: true,
        description: 'Set when the token is explicitly revoked or a refresh token family is invalidated.',
      },
    },
    {
      name: 'lastUsedAt',
      type: 'date',
      admin: {
        readOnly: true,
        description: 'Updated (best-effort) on each successful validation.',
      },
    },
    {
      name: 'parentTokenId',
      type: 'text',
      index: true,
      admin: {
        readOnly: true,
        description: 'ID of the refresh token this token replaced. Used to trace the rotation family.',
      },
    },
  ],
  labels: {
    singular: 'OAuth Token',
    plural: 'OAuth Tokens',
  },
}
