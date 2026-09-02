import type { PayloadHandler } from 'payload'
import { randomUUID } from 'crypto'
import { isLoopbackUrl } from '../lib/loopback.js'
import { oauthErrorResponse, jsonResponse, parseBody } from './helpers.js'

export function makeRegisterHandler(): PayloadHandler {
  return async (req) => {
    if (req.method !== 'POST') {
      return oauthErrorResponse(405, 'invalid_request', 'Method not allowed')
    }

    const body = await parseBody(req)

    const clientName = body['client_name']
    if (typeof clientName !== 'string' || clientName.trim() === '') {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'client_name is required')
    }
    if (clientName.length > 100) {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'client_name must not exceed 100 characters')
    }

    // redirect_uris: must be a non-empty array of strings (RFC 7591 requires JSON body)
    const rawRedirectUris = body['redirect_uris']
    if (!Array.isArray(rawRedirectUris) || rawRedirectUris.length === 0) {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'redirect_uris must be a non-empty array')
    }
    if (rawRedirectUris.length > 10) {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'redirect_uris must not contain more than 10 URIs')
    }

    const redirectUris: string[] = []
    for (const uri of rawRedirectUris) {
      if (typeof uri !== 'string') {
        return oauthErrorResponse(400, 'invalid_client_metadata', 'redirect_uris must contain strings')
      }
      if (uri.length > 2048) {
        return oauthErrorResponse(400, 'invalid_redirect_uri', 'redirect_uri exceeds maximum length of 2048 characters')
      }
      let parsed: URL
      try {
        parsed = new URL(uri)
      } catch {
        return oauthErrorResponse(400, 'invalid_redirect_uri', `Invalid redirect_uri: ${uri}`)
      }
      // RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a fragment.
      if (parsed.hash) {
        return oauthErrorResponse(400, 'invalid_redirect_uri', `redirect_uri must not contain a fragment: ${uri}`)
      }
      // Allow loopback for local development over http (RFC 8252 §7.3).
      if (parsed.protocol !== 'https:' && !isLoopbackUrl(parsed)) {
        return oauthErrorResponse(400, 'invalid_redirect_uri', `redirect_uri must use HTTPS: ${uri}`)
      }
      redirectUris.push(uri)
    }

    const authMethod = body['token_endpoint_auth_method']
    if (authMethod !== undefined && authMethod !== 'none') {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'Only token_endpoint_auth_method=none is supported')
    }

    const ALLOWED_GRANTS = new Set(['authorization_code', 'refresh_token'])
    const grantTypes = body['grant_types']
    if (grantTypes !== undefined) {
      if (!Array.isArray(grantTypes) || grantTypes.some((g) => !ALLOWED_GRANTS.has(g as string))) {
        return oauthErrorResponse(400, 'invalid_client_metadata', 'Unsupported grant_type')
      }
    }

    const responseTypes = body['response_types']
    if (responseTypes !== undefined) {
      if (!Array.isArray(responseTypes) || responseTypes.some((r) => r !== 'code')) {
        return oauthErrorResponse(400, 'invalid_client_metadata', 'Unsupported response_type')
      }
    }

    // Cap free-text client metadata that is persisted, to prevent DB bloat / DoS
    // via oversized values (mirrors the client_name cap above).
    const softwareId = body['software_id']
    if (softwareId !== undefined && (typeof softwareId !== 'string' || softwareId.length > 100)) {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'software_id must be a string of at most 100 characters')
    }
    const softwareVersion = body['software_version']
    if (softwareVersion !== undefined && (typeof softwareVersion !== 'string' || softwareVersion.length > 100)) {
      return oauthErrorResponse(400, 'invalid_client_metadata', 'software_version must be a string of at most 100 characters')
    }

    const clientId = randomUUID()
    const trimmedName = clientName.trim()

    await req.payload.create({
      collection: 'oauth-clients',
      overrideAccess: true,
      data: {
        clientId,
        clientName: trimmedName,
        redirectUris: redirectUris.map((uri) => ({ uri })),
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        softwareId: typeof softwareId === 'string' ? softwareId : undefined,
        softwareVersion: typeof softwareVersion === 'string' ? softwareVersion : undefined,
        isActive: true,
      },
    })

    return jsonResponse(
      {
        client_id: clientId,
        client_name: trimmedName,
        redirect_uris: redirectUris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      },
      201,
    )
  }
}
