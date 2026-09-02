import type { PayloadHandler } from 'payload'
import { jsonResponse } from './helpers.js'

export interface AsMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  registration_endpoint: string
  revocation_endpoint: string
  response_types_supported: ['code']
  grant_types_supported: ['authorization_code', 'refresh_token']
  code_challenge_methods_supported: ['S256']
  token_endpoint_auth_methods_supported: ['none']
  /**
   * RFC 9207. The consent redirect already carries `iss`; advertising it lets a
   * client require and verify it rather than treat it as an unexpected extra.
   */
  authorization_response_iss_parameter_supported: true
  /**
   * RFC 8414 §2 (RECOMMENDED). Omitted while scope was informational — now that
   * it narrows a grant, a client has no way to discover what it may ask for
   * without this. Absent when the server enables nothing scopable.
   */
  scopes_supported?: string[]
}

/**
 * @param apiBase Payload's API route prefix (`config.routes.api`, default
 *   `/api`). Hardcoding `/api` here made discovery advertise endpoints that do
 *   not exist whenever an app customises that route, so the caller passes the
 *   same value `plugin.ts` uses to register the endpoints.
 * @param scopesSupported Every scope token the server would grant, from
 *   `buildSupportedScopes`. Passed as plain data so this stays a pure builder
 *   with no knowledge of the MCP plugin's config shape.
 */
export function buildAsMetadata(
  baseUrl: string,
  apiBase = '/api',
  scopesSupported: string[] = [],
): AsMetadata {
  const base = baseUrl.replace(/\/$/, '')
  const api = `${base}${apiBase.startsWith('/') ? apiBase : `/${apiBase}`}`.replace(/\/$/, '')
  return {
    issuer: base,
    authorization_endpoint: `${api}/oauth/authorize`,
    token_endpoint: `${api}/oauth/token`,
    registration_endpoint: `${api}/oauth/register`,
    revocation_endpoint: `${api}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    authorization_response_iss_parameter_supported: true,
    // Omitted rather than advertised empty: `scopes_supported: []` reads as
    // "this server supports no scopes", which is not what a server with nothing
    // scopable means.
    ...(scopesSupported.length > 0 ? { scopes_supported: scopesSupported } : {}),
  }
}

export function makeAsMetadataHandler(
  issuer: string,
  apiBase = '/api',
  scopesSupported: string[] = [],
): PayloadHandler {
  const metadata = buildAsMetadata(issuer, apiBase, scopesSupported)
  return () =>
    jsonResponse(metadata, 200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET',
    })
}
