import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'

export function toCamelCase(str: string): string {
  return str
    .replace(/[-_\s]+(.)?/g, (_, chr: string) => (chr ? chr.toUpperCase() : ''))
    .replace(/^(.)/, (_, chr: string) => chr.toLowerCase())
}

/**
 * Derives the full set of MCP capabilities currently enabled by the operator.
 *
 * This is the live ceiling: it is recomputed from `mcpPluginOptions` on every
 * request, so disabling a collection takes effect immediately rather than when
 * the last token issued before the change expires.
 */
export function buildFullCapabilities(mcpPluginOptions: MCPPluginConfig): Record<string, unknown> {
  const caps: Record<string, unknown> = {}

  for (const [slug, cfg] of Object.entries(mcpPluginOptions.collections ?? {})) {
    if (!cfg) continue
    const key = toCamelCase(slug)
    if (cfg.enabled === true) {
      caps[key] = { find: true, create: true, update: true, delete: true }
    } else if (typeof cfg.enabled === 'object' && cfg.enabled !== null) {
      caps[key] = { ...cfg.enabled }
    }
  }

  for (const [slug, cfg] of Object.entries(mcpPluginOptions.globals ?? {})) {
    if (!cfg) continue
    const key = toCamelCase(slug)
    if (cfg.enabled === true) {
      caps[key] = { find: true, update: true }
    } else if (typeof cfg.enabled === 'object' && cfg.enabled !== null) {
      caps[key] = { ...cfg.enabled }
    }
  }

  return caps
}

/**
 * Narrows a token's stored grant to what the operator currently allows.
 *
 * Stored capabilities are a snapshot of the grant at consent time; the operator
 * can disable a collection (or an individual operation) at any point afterwards.
 * Without this intersection a token issued while `posts.delete` was enabled would
 * keep deleting posts for its whole lifetime after the operator turned that off —
 * the grant would outlive the permission that justified it. Applying it on every
 * request makes narrowing take effect on the next call, for scoped and full
 * grants alike.
 *
 * Only `true` on BOTH sides survives: an operation absent from, or explicitly
 * `false` in, the live config is dropped. Keys reduced to nothing are omitted
 * entirely so the result stays a clean `MCPAccessSettings` fragment.
 */
export function intersectCapabilities(
  stored: Record<string, unknown>,
  allowed: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const [key, storedOps] of Object.entries(stored)) {
    // `stored` is JSON read back from the database. Keys that would reach the
    // prototype chain are never legitimate capability names, and assigning one
    // onto the result would corrupt the MCPAccessSettings object rather than add
    // a permission. Drop them before they are used as an index.
    if (isUnsafeKey(key)) continue
    if (typeof storedOps !== 'object' || storedOps === null) continue
    if (!Object.hasOwn(allowed, key)) continue

    // eslint-disable-next-line security/detect-object-injection -- key is an own, non-prototype key of `allowed`, checked above
    const allowedOps = allowed[key]
    if (typeof allowedOps !== 'object' || allowedOps === null) continue
    const allowedRecord = allowedOps as Record<string, unknown>

    const kept: Record<string, boolean> = {}
    for (const [op, granted] of Object.entries(storedOps as Record<string, unknown>)) {
      if (isUnsafeKey(op)) continue
      // eslint-disable-next-line security/detect-object-injection -- op is an own, non-prototype key checked above; only an exact `true` grants
      if (granted === true && allowedRecord[op] === true) {
        // eslint-disable-next-line security/detect-object-injection -- as above
        kept[op] = true
      }
    }
    if (Object.keys(kept).length > 0) {
      // eslint-disable-next-line security/detect-object-injection -- key is non-prototype, checked above
      result[key] = kept
    }
  }

  return result
}

/** Keys that would walk the prototype chain instead of naming a capability. */
function isUnsafeKey(key: string): boolean {
  return key === '__proto__' || key === 'constructor' || key === 'prototype'
}

/**
 * The outcome of mapping a requested scope to MCP capabilities.
 *
 * Deliberately a discriminated union: the previous shape returned
 * `capabilities: {}` for BOTH "no scope requested" (meaning the full operator
 * grant) and "invalid scope" (meaning grant nothing). Those are opposite
 * meanings behind an identical value, and the two call sites drifted apart —
 * token issuance stored `{}` for an empty scope while `overrideAuth` read `{}`
 * as "substitute the full set". A record that says nothing about what it grants
 * cannot be audited, and a refactor that dropped either half would silently
 * change every token's authority. The `kind` tag makes the distinction
 * unforgeable at the type level.
 */
export type ScopeResult =
  /** No scope requested — RFC 6749 §3.3's "pre-defined default": the full operator grant. */
  | { kind: 'full' }
  /** A valid scope, narrowed to exactly the capabilities it names. */
  | { kind: 'scoped'; capabilities: Record<string, unknown> }
  /** At least one scope token was unknown, malformed, or not enabled on the server. */
  | { kind: 'invalid'; invalidScopes: string[] }

/**
 * Maps an OAuth scope string to narrowed MCP capabilities.
 *
 * Scope token format: "<collectionSlug>:<op>" or "<globalSlug>:<op>"
 *   read   → { find: true }
 *   write  → collections: { create: true, update: true }; globals: { update: true }
 *   delete → collections only: { delete: true }
 *
 * All requested operations must be enabled on the server — no partial grants.
 * An unknown slug, unknown operation, or disabled operation returns invalid_scope.
 *
 * Empty/absent scope returns `{ kind: 'full' }` — the caller resolves that to
 * the full operator grant via `buildFullCapabilities`. It never means "no
 * capabilities"; see the note on {@link ScopeResult}.
 */
export function scopeToCapabilities(
  scope: string,
  mcpPluginOptions: MCPPluginConfig,
): ScopeResult {
  const tokens = scope.trim().split(/\s+/).filter(Boolean)

  if (tokens.length === 0) {
    return { kind: 'full' }
  }

  const invalidScopes: string[] = []
  const capabilities: Record<string, Record<string, boolean>> = {}

  for (const token of tokens) {
    const colon = token.indexOf(':')
    if (colon <= 0 || colon === token.length - 1) {
      invalidScopes.push(token)
      continue
    }

    const slug = token.slice(0, colon)
    const op = token.slice(colon + 1)
    const key = toCamelCase(slug)

    // Try collection
    const colCfg = mcpPluginOptions.collections?.[slug]
    if (colCfg?.enabled) {
      const enabledOps: Record<string, boolean> =
        colCfg.enabled === true
          ? { find: true, create: true, update: true, delete: true }
          : (colCfg.enabled as Record<string, boolean>)
      const requestedOps = collectionOpsFor(op)
      if (!requestedOps) {
        invalidScopes.push(token)
        continue
      }
      // All requested ops must be enabled (no partial widening)
      if (!Object.entries(requestedOps).every(([k, v]) => !v || enabledOps[k])) {
        invalidScopes.push(token)
        continue
      }
      capabilities[key] = { ...(capabilities[key] ?? {}), ...requestedOps }
      continue
    }

    // Try global
    const globCfg = mcpPluginOptions.globals?.[slug]
    if (globCfg?.enabled) {
      const enabledOps: Record<string, boolean> =
        globCfg.enabled === true
          ? { find: true, update: true }
          : (globCfg.enabled as Record<string, boolean>)
      const requestedOps = globalOpsFor(op)
      if (!requestedOps) {
        invalidScopes.push(token)
        continue
      }
      if (!Object.entries(requestedOps).every(([k, v]) => !v || enabledOps[k])) {
        invalidScopes.push(token)
        continue
      }
      capabilities[key] = { ...(capabilities[key] ?? {}), ...requestedOps }
      continue
    }

    invalidScopes.push(token)
  }

  if (invalidScopes.length > 0) {
    return { kind: 'invalid', invalidScopes }
  }
  return { kind: 'scoped', capabilities: capabilities as Record<string, unknown> }
}

/**
 * Every scope token this server would accept, for `scopes_supported` in the
 * authorization-server metadata (RFC 8414 §2, RECOMMENDED).
 *
 * Scope became a real privilege boundary without ever being advertised, so a
 * client had no way to discover the scopes it could ask for and no choice but
 * to request none. Derived from the same operator config and the same
 * per-operation rules `scopeToCapabilities` enforces — a test asserts every
 * token listed here is actually grantable, and that everything grantable is
 * listed, so the advertisement cannot drift from the enforcement.
 */
export function buildSupportedScopes(mcpPluginOptions: MCPPluginConfig): string[] {
  const scopes: string[] = []

  const add = (
    slug: string,
    op: string,
    enabledOps: Record<string, boolean>,
    required: Record<string, boolean> | null,
  ) => {
    if (!required) return
    // Same "all requested ops must be enabled" rule scopeToCapabilities applies.
    if (Object.entries(required).every(([k, v]) => !v || enabledOps[k])) scopes.push(`${slug}:${op}`)
  }

  for (const [slug, cfg] of Object.entries(mcpPluginOptions.collections ?? {})) {
    if (!cfg?.enabled) continue
    const enabledOps: Record<string, boolean> =
      cfg.enabled === true
        ? { find: true, create: true, update: true, delete: true }
        : (cfg.enabled as Record<string, boolean>)
    for (const op of ['read', 'write', 'delete']) add(slug, op, enabledOps, collectionOpsFor(op))
  }

  for (const [slug, cfg] of Object.entries(mcpPluginOptions.globals ?? {})) {
    if (!cfg?.enabled) continue
    const enabledOps: Record<string, boolean> =
      cfg.enabled === true ? { find: true, update: true } : (cfg.enabled as Record<string, boolean>)
    for (const op of ['read', 'write']) add(slug, op, enabledOps, globalOpsFor(op))
  }

  return scopes
}

function collectionOpsFor(op: string): Record<string, boolean> | null {
  if (op === 'read') return { find: true }
  if (op === 'write') return { create: true, update: true }
  if (op === 'delete') return { delete: true }
  return null
}

function globalOpsFor(op: string): Record<string, boolean> | null {
  if (op === 'read') return { find: true }
  if (op === 'write') return { update: true }
  return null
}
