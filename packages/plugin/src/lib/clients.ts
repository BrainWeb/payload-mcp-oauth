import type { Payload } from 'payload'

/**
 * True when `clientId` names a registered client that is still active.
 *
 * `/authorize` has always gated on `isActive`, but token validation and refresh
 * rotation did not — so flipping the switch in the admin UI only stopped NEW
 * authorization flows while existing access tokens kept working until they
 * expired and refresh tokens kept minting replacements indefinitely. The
 * collection presents itself to operators as the place to "deactivate
 * connections", so deactivation has to cut off the live credentials too.
 *
 * Fails CLOSED: a lookup error is treated as "not active" rather than letting a
 * transient DB fault silently re-authorise a deactivated client.
 */
export async function isClientActive(payload: Payload, clientId: string): Promise<boolean> {
  if (!clientId) return false
  try {
    const { docs } = await payload.find({
      collection: 'oauth-clients',
      overrideAccess: true,
      where: {
        and: [{ clientId: { equals: clientId } }, { isActive: { equals: true } }],
      },
      limit: 1,
      pagination: false,
    })
    return docs.length > 0
  } catch {
    return false
  }
}
