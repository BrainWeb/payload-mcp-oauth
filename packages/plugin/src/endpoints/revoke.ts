import type { PayloadHandler } from 'payload'
import { hashToken } from '../lib/token-storage.js'
import { jsonResponse, parseBody } from './helpers.js'

export function makeRevokeHandler(): PayloadHandler {
  return async (req) => {
    // RFC 7009 §2.1: always 200, even on method mismatch, to avoid info leakage
    if (req.method !== 'POST') {
      return jsonResponse({})
    }

    const body = await parseBody(req)
    const token = body['token'] as string | undefined
    const clientId = body['client_id'] as string | undefined

    if (!token || typeof token !== 'string') {
      return jsonResponse({})
    }

    const hash = hashToken(token)

    const { docs } = await req.payload.find({
      collection: 'oauth-tokens',
      overrideAccess: true,
      where: { tokenHash: { equals: hash } },
      limit: 1,
    })

    const doc = docs[0]
    if (!doc) {
      return jsonResponse({})
    }

    if (clientId && doc['clientId'] !== clientId) {
      return jsonResponse({})
    }

    if (doc['revokedAt']) {
      return jsonResponse({})
    }

    const now = new Date().toISOString()
    await req.payload.update({
      collection: 'oauth-tokens',
      overrideAccess: true,
      id: String(doc['id']),
      data: { revokedAt: now },
    })

    // Revoking a refresh token also revokes the access tokens issued alongside
    // it — done by the `cascadeRevokeAccessTokens` afterChange hook on
    // `oauth-tokens`, which the update above fires. There used to be a second
    // cascade here that searched for tokens whose `parentTokenId` matched this
    // one, but that never matched anything: `issueTokenPair` stamps both members
    // of a new pair with the id of the refresh token they REPLACED, so a token's
    // sibling never carries its id, and by the time a refresh token has children
    // it has itself been revoked by rotation and returned above. It read like
    // the safety net while the hook was doing the work.

    return jsonResponse({})
  }
}
