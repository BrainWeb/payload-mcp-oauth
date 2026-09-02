import type { Plugin } from 'payload'
import { definePlugin } from 'payload'
import type { PayloadMcpOAuthConfig } from './types.js'
import { buildPlugin, isPluginDisabled } from './plugin.js'
import { installOverrideAuth } from './middleware/wrap-mcp.js'

/**
 * The slug this plugin registers under for cross-plugin discovery, mirroring
 * `@payloadcms/plugin-mcp`'s own. We rely on that affordance to detect a copied
 * `mcpPluginOptions` at boot, so it would be inconsistent not to offer it.
 */
export const PLUGIN_SLUG = 'plugin-mcp-oauth'

// `definePlugin` supplies slug + order and exposes the caller's options on the
// returned function as `.options`. It cannot own the whole factory: the plugin
// function it builds runs during config build, which is far too late for
// `installOverrideAuth` (see the note in payloadMcpOAuth below).
const definedPlugin = definePlugin<Record<string, unknown>>({
  slug: PLUGIN_SLUG,
  order: 20,
  plugin: (args) => {
    // Drop the two keys definePlugin injects; everything else is our options.
    const { config, plugins, ...options } = args
    void plugins
    return buildPlugin(config, options as unknown as PayloadMcpOAuthConfig)
  },
})

/**
 * Typed cross-plugin discovery: a plugin authored with `definePlugin` receives a
 * slug-keyed `plugins` map, and this augmentation makes our entry come back as
 * `{ options: PayloadMcpOAuthConfig }` rather than an untyped `Plugin`.
 */
declare module 'payload' {
  // Must be an `interface` (not a type alias) — module augmentation only merges
  // into interfaces.
  interface RegisteredPlugins {
    'plugin-mcp-oauth': PayloadMcpOAuthConfig
  }
}

export type { PayloadMcpOAuthConfig, ResolvedConfig } from './types.js'
export { PayloadMcpOAuthError, OAuthInvalidTokenError } from './types.js'
export type { AsMetadata } from './endpoints/metadata-as.js'
export type { PrmMetadata } from './endpoints/metadata-prm.js'
export type { RateLimitConfig, RateLimitOptions, RateLimiter } from './middleware/rate-limit.js'

/**
 * Payload plugin that adds OAuth 2.1 + PKCE + Dynamic Client Registration
 * to an existing `@payloadcms/plugin-mcp` MCP server.
 *
 * Must be registered AFTER `mcpPlugin()` in the plugins array:
 *
 * ```ts
 * const mcpOptions: MCPPluginConfig = { ... }
 *
 * export default buildConfig({
 *   plugins: [
 *     mcpPlugin(mcpOptions),
 *     payloadMcpOAuth({ issuer: 'https://cms.example.com', mcpPluginOptions: mcpOptions }),
 *   ],
 * })
 * ```
 */
export function payloadMcpOAuth(options: PayloadMcpOAuthConfig): Plugin {
  // Install overrideAuth EAGERLY (before Payload runs any plugin).
  // Payload's definePlugin spreads mcpPluginOptions into a new object when it runs the plugin
  // function, so mutations applied AFTER mcpPlugin runs are invisible to its closure.
  // By setting overrideAuth here (during the payloadMcpOAuth() call, which happens at config
  // build time before any plugin executes), it is present in mcpOptions when mcpPlugin's
  // definePlugin spreads it, and therefore captured correctly in initializeMCPHandler's closure.
  // Skip the mutation entirely when disabled (ours, or the MCP plugin's own
  // `disabled`): leave mcpPluginOptions untouched so the MCP handler runs
  // API-key-only as normal, and the app boots even if MCP itself is off.
  if (!isPluginDisabled(options) && options.mcpPluginOptions) {
    installOverrideAuth(options.mcpPluginOptions, options.userCollection ?? 'users')
  }

  // mcpPlugin uses definePlugin with order:10; ours is 20, so we run after it.
  // `definePlugin` spreads our options into a fresh object for the plugin call,
  // but `mcpPluginOptions` is copied by reference, so the identity the OAuth
  // wiring depends on is preserved.
  return definedPlugin(options as unknown as Record<string, unknown>)
}
