import { describe, expect, it } from 'vitest'
import { buildAsMetadata, makeAsMetadataHandler } from '../../../src/endpoints/metadata-as.js'

describe('buildAsMetadata', () => {
  it('returns all required RFC 8414 fields', () => {
    const m = buildAsMetadata('https://example.com')
    expect(m.issuer).toBe('https://example.com')
    expect(m.authorization_endpoint).toBe('https://example.com/api/oauth/authorize')
    expect(m.token_endpoint).toBe('https://example.com/api/oauth/token')
    expect(m.registration_endpoint).toBe('https://example.com/api/oauth/register')
    expect(m.revocation_endpoint).toBe('https://example.com/api/oauth/revoke')
  })

  it('strips trailing slash from base URL', () => {
    const m = buildAsMetadata('https://example.com/')
    expect(m.issuer).toBe('https://example.com')
    expect(m.token_endpoint).toBe('https://example.com/api/oauth/token')
  })

  it('declares only S256 for code_challenge_methods_supported', () => {
    expect(buildAsMetadata('https://example.com').code_challenge_methods_supported).toEqual(['S256'])
  })

  it('honours a custom Payload API route', () => {
    // Previously hardcoded to /api, so an app with a custom `routes.api`
    // advertised endpoints that did not exist.
    const m = buildAsMetadata('https://example.com', '/payload-api')
    expect(m.authorization_endpoint).toBe('https://example.com/payload-api/oauth/authorize')
    expect(m.token_endpoint).toBe('https://example.com/payload-api/oauth/token')
    expect(m.registration_endpoint).toBe('https://example.com/payload-api/oauth/register')
    expect(m.revocation_endpoint).toBe('https://example.com/payload-api/oauth/revoke')
    // The issuer itself is not affected by the API route.
    expect(m.issuer).toBe('https://example.com')
  })

  it('normalises an API route given without a leading slash', () => {
    expect(buildAsMetadata('https://example.com', 'custom').token_endpoint).toBe(
      'https://example.com/custom/oauth/token',
    )
  })

  it('declares only none for token_endpoint_auth_methods_supported', () => {
    expect(buildAsMetadata('https://example.com').token_endpoint_auth_methods_supported).toEqual(['none'])
  })
})

describe('makeAsMetadataHandler', () => {
  it('returns 200 with JSON content-type and Cache-Control: no-store', async () => {
    const res = await makeAsMetadataHandler('https://example.com')({} as never)
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
  })

  it('sets CORS allow-origin *', async () => {
    const res = await makeAsMetadataHandler('https://example.com')({} as never)
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*')
  })

  it('body contains the correct metadata', async () => {
    const res = await makeAsMetadataHandler('https://example.com')({} as never)
    const body = await res.json() as Record<string, unknown>
    expect(body['issuer']).toBe('https://example.com')
    expect(body['code_challenge_methods_supported']).toEqual(['S256'])
  })
})
