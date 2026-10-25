import crypto from 'crypto'
import { getPayload, handleEndpoints, type Payload } from 'payload'
import config from '@/payload.config'
import { beforeAll, describe, expect, it } from 'vitest'

// End-to-end check that a scoped grant reaches @payloadcms/plugin-mcp as the
// tools it should register. The example app enables `users` as { find, update }
// (update without create, the shape of an upload collection whose files cannot
// go over MCP) and `media` as { find, create }.
//
// Path under test: the real token endpoint resolves the code's scope to
// capabilities, the real overrideAuth narrows them to the live config, and the
// real plugin-mcp handler registers tools from the result. Only the consent
// step is skipped: the authorization code row is written directly, because
// consent needs a browser session and CSRF token that add nothing here.

const PEPPER = 'integration-test-pepper-32-chars-minimum-length'
process.env['PMOAUTH_TOKEN_PEPPER'] ||= PEPPER

const BASE = 'http://localhost:3000'
const REDIRECT_URI = 'http://127.0.0.1:33418/callback'

let payload: Payload
let clientId: string
let userId: string

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function call(path: string, init: RequestInit): Promise<Response> {
  return handleEndpoints({ config: await config, request: new Request(`${BASE}${path}`, init) })
}

/** Issues an access token for `scope` through the real token endpoint. */
async function accessTokenFor(scope: string): Promise<string> {
  const verifier = base64url(crypto.randomBytes(32))
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest())
  const code = `pmoauth_ac_${base64url(crypto.randomBytes(32))}`
  const pepper = process.env['PMOAUTH_TOKEN_PEPPER'] ?? PEPPER

  await payload.create({
    collection: 'oauth-auth-codes',
    overrideAccess: true,
    data: {
      codeHash: crypto.createHmac('sha256', pepper).update(code).digest('hex'),
      clientId,
      userId,
      redirectUri: REDIRECT_URI,
      scope,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
  })

  const res = await call('/api/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }).toString(),
  })
  const body = (await res.json()) as Record<string, unknown>
  expect(res.status, JSON.stringify(body)).toBe(200)
  return String(body['access_token'])
}

/** The tool names plugin-mcp registers for a bearer token. */
async function listTools(token: string): Promise<string[]> {
  const res = await call('/api/mcp', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  })
  const text = await res.text()
  expect(res.status, text).toBe(200)
  // The streamable HTTP transport may answer as SSE (`data: {...}`) or plain JSON.
  const json = text.includes('data:')
    ? text
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice('data:'.length).trim())
        .join('')
    : text
  const parsed = JSON.parse(json) as { result?: { tools?: Array<{ name: string }> } }
  return (parsed.result?.tools ?? []).map((t) => t.name).sort()
}

beforeAll(async () => {
  payload = await getPayload({ config: await config })

  const user = await payload.create({
    collection: 'users',
    overrideAccess: true,
    data: { email: `scoped-tools-${Date.now()}@example.com`, password: 'integration-test-password' },
  })
  userId = String(user.id)

  const res = await call('/api/oauth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Scoped tools test',
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
    }),
  })
  const body = (await res.json()) as Record<string, unknown>
  expect(res.status, JSON.stringify(body)).toBe(201)
  clientId = String(body['client_id'])
})

describe('example app: scoped grants reach plugin-mcp as tools', () => {
  it('advertises write on a collection with update but no create', async () => {
    // Payload serves it under the API route; the app's proxy rewrites the root path to it.
    const res = await call('/api/.well-known/oauth-authorization-server', { method: 'GET' })
    expect(res.status).toBe(200)
    const meta = (await res.json()) as { scopes_supported?: string[] }
    expect(meta.scopes_supported).toEqual(
      expect.arrayContaining(['users:read', 'users:write', 'media:read', 'media:write']),
    )
    expect(meta.scopes_supported).not.toContain('users:delete')
  })

  it('registers updateUsers but not createUsers for users:write', async () => {
    const tools = await listTools(await accessTokenFor('users:write'))
    expect(tools).toContain('updateUsers')
    expect(tools).not.toContain('createUsers')
    expect(tools).not.toContain('findUsers')
  })

  it('registers createMedia but not updateMedia for media:write', async () => {
    const tools = await listTools(await accessTokenFor('media:write'))
    expect(tools).toContain('createMedia')
    expect(tools).not.toContain('updateMedia')
  })
})
