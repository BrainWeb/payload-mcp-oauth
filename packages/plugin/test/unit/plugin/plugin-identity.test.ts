import { describe, expect, it } from 'vitest'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { payloadMcpOAuth, PLUGIN_SLUG } from '../../../src/index.js'
import type { PayloadMcpOAuthConfig } from '../../../src/types.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

function makeOptions(overrides: Partial<PayloadMcpOAuthConfig> = {}): PayloadMcpOAuthConfig {
  return {
    issuer: 'https://cms.example.com',
    mcpPluginOptions: {} as MCPPluginConfig,
    ...overrides,
  }
}

describe('payloadMcpOAuth — plugin metadata', () => {
  it('registers a slug for cross-plugin discovery', () => {
    const fn = payloadMcpOAuth(makeOptions()) as { slug?: string }
    expect(fn.slug).toBe(PLUGIN_SLUG)
  })

  it('runs after mcpPlugin (order 20 vs its 10)', () => {
    const fn = payloadMcpOAuth(makeOptions()) as { order?: number }
    expect(fn.order).toBe(20)
  })

  it('exposes the caller options on the plugin function', () => {
    const options = makeOptions()
    const fn = payloadMcpOAuth(options) as { options?: unknown }
    expect(fn.options).toBe(options)
  })
})

describe('payloadMcpOAuth — overrideAuth is installed EAGERLY', () => {
  it('installs overrideAuth during the payloadMcpOAuth() call, before any plugin runs', () => {
    // This is load-bearing and easy to break. Payload's definePlugin spreads the
    // options into a fresh object when it RUNS the plugin, and plugin-mcp spreads
    // again, so the MCP handler captures its copy at plugin-run time. Installing
    // overrideAuth any later lands on an object the handler has already stopped
    // reading, and OAuth silently 401s while API keys keep working.
    const mcpPluginOptions = {} as MCPPluginConfig
    expect(mcpPluginOptions.overrideAuth).toBeUndefined()

    payloadMcpOAuth(makeOptions({ mcpPluginOptions }))

    // Note: no config has been built and no plugin function has been called.
    expect(typeof mcpPluginOptions.overrideAuth).toBe('function')
  })

  it('mutates the exact object it was given, not a copy', () => {
    const mcpPluginOptions = { collections: { posts: { enabled: true } } } as MCPPluginConfig
    const fn = payloadMcpOAuth(makeOptions({ mcpPluginOptions })) as { options?: PayloadMcpOAuthConfig }
    expect(fn.options?.mcpPluginOptions).toBe(mcpPluginOptions)
    expect(mcpPluginOptions.overrideAuth).toBeDefined()
  })

  it('leaves mcpPluginOptions untouched when disabled', () => {
    const mcpPluginOptions = {} as MCPPluginConfig
    payloadMcpOAuth(makeOptions({ mcpPluginOptions, disabled: true }))
    expect(mcpPluginOptions.overrideAuth).toBeUndefined()
  })

  it('leaves mcpPluginOptions untouched when the MCP plugin itself is disabled', () => {
    const mcpPluginOptions = { disabled: true } as MCPPluginConfig
    payloadMcpOAuth(makeOptions({ mcpPluginOptions }))
    expect(mcpPluginOptions.overrideAuth).toBeUndefined()
  })
})
