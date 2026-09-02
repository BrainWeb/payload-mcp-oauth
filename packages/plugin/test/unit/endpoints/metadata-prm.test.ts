import { describe, expect, it } from 'vitest'
import { buildPrmMetadata, makePrmMetadataHandler } from '../../../src/endpoints/metadata-prm.js'

describe('buildPrmMetadata', () => {
  it('points resource and authorization_servers at the base URL', () => {
    const m = buildPrmMetadata('https://example.com')
    expect(m.resource).toBe('https://example.com')
    expect(m.authorization_servers).toEqual(['https://example.com'])
  })

  it('strips trailing slash', () => {
    expect(buildPrmMetadata('https://example.com/').resource).toBe('https://example.com')
  })

  it('declares bearer_methods_supported: [header]', () => {
    expect(buildPrmMetadata('https://example.com').bearer_methods_supported).toEqual(['header'])
  })
})

describe('makePrmMetadataHandler', () => {
  it('returns 200 with Cache-Control: no-store and CORS header', async () => {
    const res = await makePrmMetadataHandler('https://example.com')({} as never)
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*')
  })

  it('body contains resource pointing to issuer', async () => {
    const res = await makePrmMetadataHandler('https://example.com')({} as never)
    const body = await res.json() as Record<string, unknown>
    expect(body['resource']).toBe('https://example.com')
    expect(body['authorization_servers']).toEqual(['https://example.com'])
  })
})

describe('buildPrmMetadata — scope advertisement', () => {
  it('advertises the scopes the resource understands', () => {
    expect(buildPrmMetadata('https://example.com', ['posts:read']).scopes_supported).toEqual(['posts:read'])
  })

  it('omits scopes_supported entirely when nothing is scopable', () => {
    expect(buildPrmMetadata('https://example.com')).not.toHaveProperty('scopes_supported')
  })
})
