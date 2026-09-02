import type { Plugin } from 'payload'
import type { PayloadMcpOAuthConfig } from './types.js'
import { buildPlugin, isPluginDisabled } from './plugin.js'
import { installOverrideAuth } from './middleware/wrap-mcp.js'

/**
 * The slug this plugin registers under for cross-plugin discovery, mirroring
 * `@payloadcms/plugin-mcp`'s own. We rely on that affordance to detect a copied
 * `mcpPluginOptions` at boot, so it would be inconsistent not to offer it.
 */
export const PLUGIN_SLUG = 'plugin-mcp-oauth'

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

  // `slug`, `order` and `options` are set by hand rather than via Payload's
  // `definePlugin`. That helper only exists from payload 3.83.0, and our peer
  // range is ^3.0.0 — importing it would break every consumer below that with a
  // module-load error (`does not provide an export named 'definePlugin'` on ESM,
  // `definePlugin is not a function` on CJS). It is also still marked
  // @experimental upstream. Setting the three properties directly produces the
  // same plugin function with no version floor, and keeps `options` as the exact
  // object the caller passed rather than definePlugin's spread copy.
  //
  // mcpPlugin runs at order 10; ours is 20, so we run after it.
  const fn: Plugin = (incomingConfig) => buildPlugin(incomingConfig, options)
  fn.slug = PLUGIN_SLUG
  fn.order = 20
  fn.options = options as unknown as Record<string, unknown>
  return fn
}
