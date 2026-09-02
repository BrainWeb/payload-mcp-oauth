import { describe, expect, it } from 'vitest'
import { isLoopbackHostname, isLoopbackUrl } from '../../../src/lib/loopback.js'

describe('isLoopbackHostname', () => {
  it('accepts the three loopback hosts', () => {
    expect(isLoopbackHostname('localhost')).toBe(true)
    expect(isLoopbackHostname('127.0.0.1')).toBe(true)
    expect(isLoopbackHostname('[::1]')).toBe(true)
  })

  it('rejects hostnames that merely contain a loopback name', () => {
    // The check gates an HTTPS exemption, so a near-miss must not pass.
    expect(isLoopbackHostname('localhost.evil.com')).toBe(false)
    expect(isLoopbackHostname('notlocalhost')).toBe(false)
    expect(isLoopbackHostname('127.0.0.1.evil.com')).toBe(false)
    expect(isLoopbackHostname('evil.com')).toBe(false)
  })

  it('rejects other addresses in the loopback range and unbracketed IPv6', () => {
    // Deliberately narrow — only the hosts the specs name.
    expect(isLoopbackHostname('127.0.0.2')).toBe(false)
    expect(isLoopbackHostname('::1')).toBe(false)
    expect(isLoopbackHostname('0.0.0.0')).toBe(false)
  })

  it('rejects the empty string', () => {
    expect(isLoopbackHostname('')).toBe(false)
  })
})

describe('isLoopbackUrl', () => {
  it('reads the hostname from a parsed URL, ignoring port and scheme', () => {
    expect(isLoopbackUrl(new URL('http://localhost:3000/api'))).toBe(true)
    expect(isLoopbackUrl(new URL('https://127.0.0.1/'))).toBe(true)
    expect(isLoopbackUrl(new URL('http://[::1]:8080/x'))).toBe(true)
    expect(isLoopbackUrl(new URL('https://cms.example.com'))).toBe(false)
  })

  it('matches what URL.hostname reports for IPv6 (bracketed)', () => {
    expect(new URL('http://[::1]:3000').hostname).toBe('[::1]')
    expect(isLoopbackUrl(new URL('http://[::1]:3000'))).toBe(true)
  })
})
