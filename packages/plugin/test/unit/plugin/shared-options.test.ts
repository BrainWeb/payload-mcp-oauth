import { describe, expect, it } from 'vitest'
import { mcpPlugin } from '@payloadcms/plugin-mcp'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { buildPlugin } from '../../../src/plugin.js'
import { PayloadMcpOAuthError } from '../../../src/types.js'

process.env['PMOAUTH_TOKEN_PEPPER'] = 'test-pepper-32-chars-minimum-length!!'

/**
 * These run against the REAL `@payloadcms/plugin-mcp`, not a stand-in.
 *
 * The copied-options check reads `.slug` and `.options` off the plugin function,
 * both of which are set by Payload's `definePlugin` — an implementation detail of
 * another package. A stand-in would keep passing if that shape ever changed,
 * which is precisely when the check would start silently doing nothing.
 */
function buildRealMcpConfig(mcpOptions: MCPPluginConfig) {
  const pluginFn = mcpPlugin(mcpOptions)
  const base = { collections: [], endpoints: [], plugins: [pluginFn] } as unknown as import('payload').Config
  // Run the MCP plugin exactly as buildConfig would, so /mcp is registered.
  return { pluginFn, config: pluginFn(base) as import('payload').Config }
}

describe('copied mcpPluginOptions detection — against the real plugin-mcp', () => {
  it('definePlugin still exposes the consumer options by identity', () => {
    // The premise the whole check rests on.
    const mcpOptions: MCPPluginConfig = { collections: { posts: { enabled: true } } }
    const { pluginFn } = buildRealMcpConfig(mcpOptions)
    expect((pluginFn as unknown as { slug?: string }).slug).toBe('@payloadcms/plugin-mcp')
    expect((pluginFn as unknown as { options?: unknown }).options).toBe(mcpOptions)
  })

  it('accepts the shared reference the docs tell you to use', () => {
    const mcpOptions: MCPPluginConfig = { collections: { posts: { enabled: true } } }
    const { config } = buildRealMcpConfig(mcpOptions)
    expect(() =>
      buildPlugin(config, { issuer: 'https://cms.example.com', mcpPluginOptions: mcpOptions }),
    ).not.toThrow()
  })

  it('rejects a spread copy with a clear error instead of failing silently at runtime', () => {
    const mcpOptions: MCPPluginConfig = { collections: { posts: { enabled: true } } }
    const { config } = buildRealMcpConfig(mcpOptions)
    expect(() =>
      buildPlugin(config, { issuer: 'https://cms.example.com', mcpPluginOptions: { ...mcpOptions } }),
    ).toThrow(PayloadMcpOAuthError)
  })

  it('rejects a fresh literal that happens to be deeply equal', () => {
    // Deep equality is not enough — it is the object identity that matters.
    const mcpOptions: MCPPluginConfig = { collections: { posts: { enabled: true } } }
    const { config } = buildRealMcpConfig(mcpOptions)
    expect(() =>
      buildPlugin(config, {
        issuer: 'https://cms.example.com',
        mcpPluginOptions: { collections: { posts: { enabled: true } } },
      }),
    ).toThrow(/same object you passed to mcpPlugin/)
  })
})
