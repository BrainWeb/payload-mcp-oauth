import type { Access, CollectionAfterChangeHook, CollectionConfig } from 'payload'

// Managed server-side only (plugin endpoints use overrideAccess; no admin view
// reads this). Deny all public REST/GraphQL access — see clients.ts for the
// rationale (previously any authenticated user could read/tamper these rows).
const denyPublicAccess: Access = () => false

// A single bulk delete rather than two finds plus N individual deletes, matching
// the sweep in csrf-nonces.ts — the two collections hold the same kind of
// short-lived single-use row and had opposite implementations, with the nonce
// sweep's own comment explaining why find + N deletes is the wrong shape (write
// amplification and lock contention on every insert).
const sweepExpiredCodes: CollectionAfterChangeHook = async ({ operation, req }) => {
  if (operation !== 'create') return

  try {
    await req.payload.delete({
      collection: 'oauth-auth-codes',
      overrideAccess: true,
      where: {
        or: [
          { expiresAt: { less_than: new Date().toISOString() } },
          { consumedAt: { exists: true } },
        ],
      },
      req,
    })
  } catch {
    // Best-effort housekeeping; never block auth-code issuance on it.
  }
}

export const oauthAuthCodesCollection: CollectionConfig = {
  slug: 'oauth-auth-codes',
  // Server-managed — opt out of document-locking so no FK column is added to
  // payload_locked_documents_rels (avoids the SQLite push rebuild bug; see clients.ts).
  lockDocuments: false,
  admin: {
    hidden: true,
  },
  access: {
    create: denyPublicAccess,
    read: denyPublicAccess,
    update: denyPublicAccess,
    delete: denyPublicAccess,
  },
  timestamps: false,
  hooks: {
    afterChange: [sweepExpiredCodes],
  },
  fields: [
    {
      name: 'codeHash',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      admin: {
        readOnly: true,
        description: 'HMAC-SHA-256 hash of the authorization code plaintext.',
      },
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
      name: 'redirectUri',
      type: 'text',
      required: true,
      admin: { readOnly: true },
    },
    {
      name: 'scope',
      type: 'text',
      admin: { readOnly: true },
    },
    {
      name: 'codeChallenge',
      type: 'text',
      required: true,
      admin: { readOnly: true },
    },
    {
      name: 'codeChallengeMethod',
      type: 'select',
      required: true,
      defaultValue: 'S256',
      admin: { readOnly: true },
      options: [{ label: 'S256', value: 'S256' }],
    },
    {
      name: 'expiresAt',
      type: 'date',
      required: true,
      index: true,
      admin: { readOnly: true },
    },
    {
      name: 'consumedAt',
      type: 'date',
      admin: {
        readOnly: true,
        description: 'Set when the code is exchanged. Null means it has not been used.',
      },
    },
  ],
  labels: {
    singular: 'Auth Code',
    plural: 'Auth Codes',
  },
}
