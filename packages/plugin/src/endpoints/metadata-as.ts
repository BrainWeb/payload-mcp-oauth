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
}

/**
 * @param apiBase Payload's API route prefix (`config.routes.api`, default
 *   `/api`). Hardcoding `/api` here made discovery advertise endpoints that do
 *   not exist whenever an app customises that route, so the caller passes the
 *   same value `plugin.ts` uses to register the endpoints.
 */
export function buildAsMetadata(baseUrl: string, apiBase = '/api'): AsMetadata {
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
  }
}

export function makeAsMetadataHandler(issuer: string, apiBase = '/api'): PayloadHandler {
  const metadata = buildAsMetadata(issuer, apiBase)
  return () =>
    jsonResponse(metadata, 200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET',
    })
}
