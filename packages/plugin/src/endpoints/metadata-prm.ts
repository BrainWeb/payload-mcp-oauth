import type { PayloadHandler } from 'payload'
import { jsonResponse } from './helpers.js'

export interface PrmMetadata {
  resource: string
  authorization_servers: [string]
  bearer_methods_supported: ['header']
  resource_documentation?: string
  /** RFC 9728 §2 (RECOMMENDED) — the scopes this resource understands. */
  scopes_supported?: string[]
}

export function buildPrmMetadata(baseUrl: string, scopesSupported: string[] = []): PrmMetadata {
  const base = baseUrl.replace(/\/$/, '')
  return {
    resource: base,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
    ...(scopesSupported.length > 0 ? { scopes_supported: scopesSupported } : {}),
  }
}

export function makePrmMetadataHandler(issuer: string, scopesSupported: string[] = []): PayloadHandler {
  const metadata = buildPrmMetadata(issuer, scopesSupported)
  return () =>
    jsonResponse(metadata, 200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET',
    })
}
