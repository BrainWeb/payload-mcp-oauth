# @brainwebuk/payload-plugin-mcp-oauth

OAuth 2.1 + PKCE + Dynamic Client Registration for
[`@payloadcms/plugin-mcp`](https://www.npmjs.com/package/@payloadcms/plugin-mcp),
so a Payload-backed MCP server can be added as a **Custom Connector in Claude.ai**
alongside the existing API-key flow.

The plugin is **purely additive**: it wraps the MCP endpoint handler and adds the
OAuth endpoints and collections. Your existing API-key MCP clients keep working
unchanged.

- OAuth 2.1 authorization-code flow with **PKCE (S256 only)**
- **Dynamic Client Registration** (RFC 7591) — Claude.ai self-registers
- Discovery via RFC 8414 / RFC 9728 well-known documents
- Tokens hashed at rest (HMAC-SHA-256); refresh + revocation supported
- **OAuth Clients** and **OAuth Tokens** appear as admin collections under the
  **MCP** nav group (admin-only; the public REST/GraphQL surface stays closed)

> **Installing with an AI coding agent?** Point it at
> [`INSTALL_FOR_AGENTS.md`](./INSTALL_FOR_AGENTS.md) (shipped in this
> npm package) — a step-by-step playbook with per-step verification and the
> failure modes to watch for. Or just follow the manual steps below.

---

## Requirements

| | Version |
|---|---|
| `payload` | `^3.0.0` |
| `@payloadcms/plugin-mcp` | `^3.0.0` (tested 3.85.0) |
| `next` | `^14 \|\| ^15 \|\| ^16` (only for the exported proxy/middleware) |
| Node | `>= 20` |

---

## Install

### 1. Add the package

```bash
pnpm add @brainwebuk/payload-plugin-mcp-oauth
# or: npm i / yarn add
```

### 2. Register the plugin (after `mcpPlugin`)

In `payload.config.ts`, register `payloadMcpOAuth()` **immediately after**
`mcpPlugin()`, and pass it the **same** options object you gave to `mcpPlugin()`.

```ts
import { mcpPlugin } from '@payloadcms/plugin-mcp'
import type { MCPPluginConfig } from '@payloadcms/plugin-mcp'
import { payloadMcpOAuth } from '@brainwebuk/payload-plugin-mcp-oauth'
import { buildConfig } from 'payload'

// Assign ONCE to a const and reuse the same reference in both calls. ⚠️
const mcpOptions: MCPPluginConfig = {
  collections: {
    users: { enabled: { find: true, update: true } },
    media: { enabled: { find: true, create: true } },
  },
}

export default buildConfig({
  // ...db, collections, admin, etc.
  plugins: [
    mcpPlugin(mcpOptions),
    payloadMcpOAuth({
      issuer: process.env.NEXT_PUBLIC_SERVER_URL || 'http://localhost:3000',
      mcpPluginOptions: mcpOptions, // ← the SAME object, not a copy
    }),
  ],
})
```

> ⚠️ **Pass the same object reference to both calls.** The plugin installs its
> token-validation hook by mutating `mcpOptions`. If you pass a fresh object or a
> spread/copy to either call, OAuth tokens will silently fail to authenticate
> (the API-key path keeps working, which makes this easy to miss). The plugin
> also throws on boot if it is registered *before* `mcpPlugin()`.

> **Design note — why we mutate `mcpPluginOptions`.** Payload's plugin guidance
> says "never mutate the incoming config," and everything this plugin *adds*
> (collections, endpoints) is done by spreading the incoming config, not mutating
> it. The one deliberate exception is `mcpPluginOptions`: the OAuth token
> validator has to live inside `@payloadcms/plugin-mcp`'s request-handler closure,
> which Payload captures when *that* plugin runs — so we must set `overrideAuth` on
> the shared options object *before* `mcpPlugin()` executes (hence the
> same-reference rule above). This mutates a **sibling plugin's** options, which the
> [Plugin API](https://payloadcms.com/docs/plugins/plugin-api) explicitly permits
> (`plugins['…']?.options`), rather than our own incoming config. It's the most
> fragile part of the setup, so we're tracking less-footgun-prone alternatives in
> [issue #51](https://github.com/BrainWeb/payload-mcp-oauth/issues/51).

### 3. Add the proxy (Next.js 16) / middleware (Next.js 14–15)

OAuth discovery (`/.well-known/...`) and bare-host MCP connectors need two
host-level URL rewrites that a Payload plugin cannot register on its own. The
plugin ships them as a ready-made request handler — wire it up with the file
convention your Next.js version uses (next to your `app/` directory). Re-export
the handler, but declare `config` as a **local** literal.

**Next.js 16+** — Next renamed the `middleware` convention to `proxy`. Create
`src/proxy.ts`:

```ts
export { mcpOAuthMiddleware as proxy } from '@brainwebuk/payload-plugin-mcp-oauth/middleware'

export const config = {
  matcher: [
    '/',
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-protected-resource',
  ],
}
```

**Next.js 14–15** — the `proxy` convention doesn't exist yet; create
`src/middleware.ts` with the same body, exported as `middleware`:

```ts
export { mcpOAuthMiddleware as middleware } from '@brainwebuk/payload-plugin-mcp-oauth/middleware'

export const config = {
  matcher: [
    '/',
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-protected-resource',
  ],
}
```

> ⚠️ **Don't re-export `config`** (e.g. `export { ..., config } from '…/middleware'`).
> Next.js parses the matcher at compile time and, as of **Next 16**, hard-errors
> with *"can't recognize the exported `config` field … it mustn't be reexported"*
> — which 500s **every** route in your app. The matcher must be a static literal
> in your `proxy.ts` / `middleware.ts` itself.
>
> On Next 16 a `middleware.ts` still works but logs a deprecation warning — prefer
> `proxy.ts`. Migrate an existing file with `npx @next/codemod middleware-to-proxy .`.

Already have a proxy/middleware? Compose it instead (shown for Next 16; on 14–15
name the file `middleware.ts` and the function `middleware`):

```ts
import type { NextRequest } from 'next/server'
import { createMcpOAuthMiddleware } from '@brainwebuk/payload-plugin-mcp-oauth/middleware'

const mcpOAuth = createMcpOAuthMiddleware() // accepts { apiRoute, mcpEndpointPath, ... }

export function proxy(request: NextRequest) {
  // ...your logic first...
  return mcpOAuth(request)
}

export const config = {
  matcher: ['/', '/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource' /* + yours */],
}
```

> No `next.config.ts` rewrites are required — the proxy/middleware handles discovery.

### 4. Set environment variables

```bash
# Public HTTPS URL clients reach. Used as the OAuth issuer + in discovery metadata.
NEXT_PUBLIC_SERVER_URL=https://cms.example.com

# HMAC pepper for hashing tokens at rest — REQUIRED in production (>= 32 chars).
# Generate with: openssl rand -hex 32
PMOAUTH_TOKEN_PEPPER=<64-hex-chars>
```

In development a built-in insecure pepper is used if `PMOAUTH_TOKEN_PEPPER` is
unset (with a warning). In `NODE_ENV=production` the plugin **throws on boot** if
it is missing or shorter than 32 characters.

> **Set `PMOAUTH_TOKEN_PEPPER` locally too.** `next build` and `next start` set
> `NODE_ENV=production` whether or not you are deploying, so a local production
> build hits the same boot check. Put the pepper in your local `.env` and
> `pnpm build` works on your machine.
>
> A `http://localhost` (or `127.0.0.1` / `[::1]`) issuer is *exempt* from the
> HTTPS requirement for exactly this reason — a loopback URL is not reachable off
> your machine, so there is no transport to protect. Any other host still has to
> be `https://` under `NODE_ENV=production`.

> **Keep `serverURL` consistent.** The authorize/consent flow signs the user in
> with a first-party Payload **session cookie**, so Payload's `serverURL` must be
> the same public origin clients reach (the same value as `NEXT_PUBLIC_SERVER_URL`).
> Most starters already do this via `getServerSideURL()`. If `serverURL` doesn't
> match the origin the browser actually uses, the consent **Approve** POST can
> lose its session — see Troubleshooting.

### 5. Regenerate the admin import map (if your app uses one)

This plugin registers no custom admin components, so it doesn't *require* an import
map regeneration. If your app already maintains `src/app/(payload)/admin/importMap.js`,
regenerating it after installing is harmless and keeps it tidy:

```bash
pnpm payload generate:importmap
```

(Drop the `src/` prefix if your app doesn't use a `src` directory.)

### 6. Apply the schema change

The plugin adds collections (`oauth-clients`, `oauth-auth-codes`, `oauth-tokens`,
`oauth-csrf-nonces`). Use whichever schema workflow your app already uses — **don't
mix them**:

- **Dev push** (default for SQLite/Postgres in dev): just start the app; the new
  tables are pushed on next boot. Do **not** run `migrate:create`/`migrate` against
  a push-synced dev DB — you'll get *"table … already exists"*.
- **Migrations** (production): run `pnpm payload migrate:create` to generate a
  migration that includes the new collections, then `pnpm payload migrate`.

That's it — start the app and the OAuth endpoints are live, with **OAuth Clients**
and **OAuth Tokens** under the **MCP** group in the admin sidebar.

---

## Connect from Claude.ai

1. Settings → **Connectors** → **Add custom connector**.
2. Enter your server URL (the bare host, e.g. `https://cms.example.com`, works —
   the middleware routes it to the MCP endpoint).
3. Claude.ai discovers the auth server, dynamically registers, and starts the
   OAuth + PKCE handshake.
4. You'll be sent to your Payload admin login + a consent screen; approve to
   issue a token.

Verify discovery is reachable:

```bash
curl https://cms.example.com/.well-known/oauth-protected-resource
curl https://cms.example.com/.well-known/oauth-authorization-server
```

---

## Making the MCP usable for AI agents

Once connected, an agent only knows what the MCP server *tells* it. Tools
generated from rich collections (a page builder with nested blocks, conditional
fields, etc.) are large and non-obvious, so agents trial-and-error their way
through `create*` calls. Close that gap with the guidance channels
`@payloadcms/plugin-mcp` exposes — all delivered **server → agent** over the
protocol, so they reach every client (Claude.ai web, Desktop, Code, and
non-Claude MCP clients):

- **`serverOptions.instructions`** — a "how to use this server" string on `mcpPlugin()`.
- **per-collection `description`** — tells the agent when/why to use a collection.
- **field `admin.description`** — flows into each tool's input schema, so the
  agent reads field rules inline (e.g. "required only when …").
- **`prompts`** — pre-baked, guided workflows the agent can invoke.

```ts
mcpPlugin({
  serverOptions: {
    serverInfo: { name: 'Author Website', version: '1.0.0' },
    instructions: `
This server manages an author marketing site (pages, posts, media).
- Publish by setting "_status": "published".
- pages.hero.type is none|lowImpact|mediumImpact|highImpact; high/mediumImpact
  REQUIRE hero.media (a Media id) — upload first; prefer lowImpact otherwise.
- pages.layout is an array of blocks: content, cta, mediaBlock, archive, formBlock.
- If a tool schema is large, create a minimal doc first, then add blocks with the update tool.`,
  },
  collections: {
    pages: {
      description: 'Landing/marketing pages built from a hero + layout blocks.',
      enabled: { find: true, create: true, update: true },
    },
  },
})
```

> **Why not ship a Claude Skill for this?** Skills load only from the *consuming*
> client's own environment — an MCP server (or this npm package) cannot push a
> Skill to a connecting Claude.ai/Desktop agent. `instructions`/`prompts` are the
> protocol-native equivalent and reach every client automatically. (A Skill *is*
> useful for the **install** experience — see below.)

### Install helper for Claude Code (optional)

The [project repo](https://github.com/BrainWeb/payload-mcp-oauth) doubles as a
Claude Code plugin marketplace with an `install` skill that walks Claude Code
through wiring up the plugin (config, proxy, env, schema) and the common
pitfalls. In Claude Code:

```
/plugin marketplace add BrainWeb/payload-mcp-oauth
/plugin install payload-mcp-oauth@brainwebuk
```

Then ask Claude Code to "install payload-plugin-mcp-oauth" (or run
`/payload-mcp-oauth:install`). This helps the **developer** installing the plugin;
because Skills are client-side it has no effect on the runtime connector agent.

---

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `issuer` | `string` | — (required) | Public base URL; OAuth issuer + metadata base. |
| `mcpPluginOptions` | `MCPPluginConfig` | — (required) | The **same** object passed to `mcpPlugin()`. |
| `userCollection` | `string` | `'users'` | Collection holding user accounts. |
| `disabled` | `boolean` | `false` | Turn OAuth off without uninstalling: no endpoints, no token wiring, `mcpPluginOptions` untouched (API-key MCP keeps working). Collections stay registered for schema consistency. Also auto-detected when `mcpPluginOptions.disabled` is set. |
| `adminAccess` | `Access` | member of `userCollection` who passes the role check | Who may view/manage the OAuth collections in the admin. Honours a `role`/`isAdmin`/`roles` field when your collection has one. See below. |
| `loginPath` | `string` | `routes.admin` + `admin.routes.login` | Where to send an unauthenticated user to sign in. Derived from your Payload config, so a custom admin or login route is picked up automatically. Set it only if sign-in lives outside the admin panel. |
| `accessTokenTtlSeconds` | `number` | `3600` | Access-token lifetime. |
| `refreshTokenTtlSeconds` | `number` | `86400` | Refresh-token lifetime. |
| `authCodeTtlSeconds` | `number` | `300` | Authorization-code lifetime. |
| `rateLimits` | `RateLimitOptions` | `{}` | Per-endpoint rate-limit overrides. Per-process and in-memory — see the caveat below. |

### Scopes

A client may request a narrowed grant with a space-separated `scope`, where each
token is `<collection-or-global-slug>:<operation>`:

| Scope token | Grants (collections) | Grants (globals) |
|---|---|---|
| `<slug>:read` | `find` | `find` |
| `<slug>:write` | `create` + `update` | `update` |
| `<slug>:delete` | `delete` | — (rejected) |

```
scope=posts:read posts:write media:read
```

**Requesting no scope grants everything the operator has enabled** — RFC 6749
§3.3's pre-defined default, and what Claude.ai's Custom Connector does. The
consent screen says which of the two is happening.

Scope can only ever *narrow*:

- Every operation a token names must be enabled on the server, or the whole
  request is rejected with `invalid_scope` — there are no partial grants. A
  collection with only `find` enabled offers `:read` and refuses `:write`.
- The scope is validated at `/authorize`, re-validated at `/consent` (so
  tampering with the hidden form field is caught), and resolved again when the
  code is redeemed.
- The granted capabilities are intersected with your **live** config on every
  request, so disabling a collection narrows existing tokens on their next call
  rather than when they expire.

The exact set your server accepts is published in
`/.well-known/oauth-authorization-server` as `scopes_supported`, derived from
your `mcpPluginOptions` — so you never have to maintain the list by hand.

### Rate limits

The built-in limiters are a speed bump against casual abuse, not a security
control — PKCE, the single-use CSRF nonce and the session gate are what protect
the flow. Two caveats worth knowing before you rely on them:

- **Buckets are keyed on `x-forwarded-for`,** which is client-supplied unless
  something upstream overwrites it. Behind a proxy or load balancer that sets the
  header itself, the limits hold; exposed directly to the internet, a caller can
  rotate the header for a fresh quota per request.
- **Buckets live in one process's memory.** Across several instances the
  effective ceiling is your configured limit times the instance count, and on
  serverless every cold start begins with empty buckets.

If you need limits that actually bind, put them in front of the app — at your
proxy, CDN or WAF.

### Admin UI & access

`oauth-clients` and `oauth-tokens` render as collections under the **MCP** nav
group (alongside the MCP plugin's API Keys). `read`/`update`/`delete` are gated by
`adminAccess`; `create` is always denied (clients self-register via DCR, tokens are
minted by the token endpoint). `oauth-auth-codes` and `oauth-csrf-nonces` stay
hidden and fully locked.

The default `adminAccess` denies the public REST/GraphQL surface and authorises an
authenticated user who is **in your `userCollection`** *and* passes an admin
check that honours whichever role field your collection has:

| Your user collection has | Default rule authorises |
|---|---|
| a `role` field | `role === 'admin'` |
| an `isAdmin` field | `isAdmin === true` |
| a `roles` array | `roles` includes `'admin'` |
| none of the above | any member of the collection |

So the standard Payload starters (no role field) are unaffected, while apps that
already carry roles get the tighter gate automatically.

⚠️ **If your operators carry a role other than `admin`** — `editor`, `owner`,
`staff` — this default locks them out of the OAuth screens. Pass your own rule.

⚠️ **If your `userCollection` mixes admins with untrusted end-users** and has no
role field, the default reduces to "any logged-in user", who could then rewrite a
client's `redirectUris` (→ auth-code theft) or revoke others' tokens. Pass your
own rule:

```ts
payloadMcpOAuth({
  issuer,
  mcpPluginOptions: mcpOptions,
  adminAccess: ({ req }) => req.user?.role === 'admin',
})
```

### Endpoints added

`GET /.well-known/oauth-authorization-server`, `GET /.well-known/oauth-protected-resource`,
`POST /api/oauth/register`, `GET /api/oauth/authorize`, `POST /api/oauth/consent`,
`POST /api/oauth/token`, `POST /api/oauth/revoke`.

OAuth tokens use the `pmoauth_` prefix. The MCP handler checks the Bearer value:
`pmoauth_…` takes the OAuth path; anything else delegates to the original API-key
handler unchanged.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Error: payloadMcpOAuth must be registered AFTER mcpPlugin()` | Plugin order — put `payloadMcpOAuth()` after `mcpPlugin()`. |
| OAuth tokens 401 but API keys work | `mcpPluginOptions` wasn't the **same** object reference (step 2). |
| `/.well-known/...` returns the app's HTML / 404 | `proxy.ts` / `middleware.ts` missing or its `matcher` doesn't include the well-known paths (step 3). |
| **Every** route 500s; log says *"can't recognize the exported `config` field … it mustn't be reexported"* | `config` was re-exported from `…/middleware` instead of declared as a local literal in your `proxy.ts` / `middleware.ts` (step 3). |
| `The "middleware" file convention is deprecated` warning (Next 16) | Rename `src/middleware.ts` → `src/proxy.ts` and export the handler as `proxy` (step 3). |
| Consent screen renders, but **Approve** returns `401 access_denied / "Authentication required"` | Plugin bug in **≤ 0.3.0**: the consent page sent `Referrer-Policy: no-referrer`, so browsers sent `Origin: null` on the Approve POST and Payload dropped the session (the `GET` render has no `Origin`, so it worked; the `POST` didn't). **Fixed in 0.3.1 — upgrade.** If it persists on ≥ 0.3.1, your `serverURL` doesn't match the origin the browser uses — check `NEXT_PUBLIC_SERVER_URL` (exact scheme + host, no trailing slash). |
| **OAuth Clients / OAuth Tokens** missing from the admin nav, or their route shows *"Nothing found"* | The logged-in user isn't authorised by `adminAccess`. By default they must belong to `userCollection`; for mixed-role apps pass a custom `adminAccess` (see *Admin UI & access*). |
| `migrate` fails with *"table … already exists"* | You ran `migrate` against a DB already created by dev push — pick one workflow (step 6). |
| `SQLITE_ERROR: no such column: oauth_clients_id` while rebuilding `payload_locked_documents_rels` on `pnpm dev` | SQLite push can't add the new collections' lock-FK columns to an **already-pushed** DB (a Payload/drizzle rebuild quirk). **Fixed in 0.3.2** — the OAuth collections set `lockDocuments: false`, so they add no column there. On ≤ 0.3.1: add the plugin *before* first boot, or reset the dev DB (`rm your.db*`) so the schema is created fresh. |
| Boots fine in dev, throws on deploy | `PMOAUTH_TOKEN_PEPPER` not set in production (step 4). |

---

## License

MIT
