#!/usr/bin/env node
// Stand up the freshly-installed test site and leave it running so you can open
// it in a browser. Same install path as `pnpm test:install` (it shares
// ./lib/provision.mjs), but instead of running the OAuth handshake it boots
// `next dev` in the foreground and prints the URL + admin login.
//
// Usage:  pnpm test:install:serve            # http://localhost:3000
//         pnpm test:install:serve -- --port 4000
//         pnpm test:install:serve -- --reuse # reuse the prior install (faster)
//         pnpm test:install:serve -- --live  # expose a public HTTPS URL via a
//                                            # Cloudflare tunnel and use it as the
//                                            # OAuth issuer, so you can add the site
//                                            # as a Custom Connector in Claude.ai
//
// The app lives in a randomly-created temp dir recorded in .serve-dir next to
// this script. It is reprovisioned from the freshly packed plugin on every launch
// by default, so you can never click around a stale build (the false-positive
// that masked the #33 locked-collection regression — see issue #43). Pass
// --reuse to keep the prior install (node_modules + DB) for a fast restart when
// you KNOW the plugin is unchanged. Press Ctrl+C to stop.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  ADMIN,
  INSTALL_ROOT,
  LOCKFILE,
  freePort,
  isProvisioned,
  makeAppEnv,
  portFree,
  provisionApp,
  readEnv,
  refreshAppSource,
  restoreLockfile,
  seedAndMigrate,
  startCloudflaredTunnel,
  startDevServer,
  waitForServer,
  writeEnv,
} from './lib/provision.mjs'

function argValue(name, fallback) {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback
}
const REUSE = process.argv.includes('--reuse')
const LIVE = process.argv.includes('--live')
const wantedPort = Number(argValue('--port', '3000'))

// Pointer file that records the random temp dir across --reuse invocations.
// Lives next to this script (not inside tmpdir) so it is not subject to CWE-377.
const SERVE_PTR = path.join(INSTALL_ROOT, '.serve-dir')
function readServeRoot() {
  try { return readFileSync(SERVE_PTR, 'utf8').trim() } catch { return null }
}

const lockfileSnapshot = readFileSync(LOCKFILE, 'utf8')

let server
let tunnel
let shuttingDown = false
function shutdown() {
  if (shuttingDown) return
  shuttingDown = true
  if (server) {
    try {
      // startDevServer runs detached, so kill the whole process group.
      process.kill(-server.pid, 'SIGKILL')
    } catch {
      /* already gone */
    }
  }
  if (tunnel?.proc) {
    // cloudflared is detached too — kill the whole group.
    try {
      process.kill(-tunnel.proc.pid, 'SIGKILL')
    } catch {
      /* already gone */
    }
  }
  // Safety net for the provisioning-failure path (provisionApp threw before the
  // eager restore below ran). A no-op once the eager restore has already cleaned
  // the lockfile — restoreLockfile only writes when it actually differs.
  if (restoreLockfile(lockfileSnapshot)) {
    console.log('\nRestored repo pnpm-lock.yaml.')
  }
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

try {
  const port = (await portFree(wantedPort)) ? wantedPort : await freePort()
  if (port !== wantedPort) console.log(`Port ${wantedPort} is busy → using ${port} instead.`)
  const baseUrl = `http://localhost:${port}`

  // --live: bring up a public HTTPS tunnel BEFORE provisioning so the app is
  // provisioned with the tunnel URL as its OAuth issuer (+ Payload serverURL).
  // The dev server still binds localhost:port; cloudflared forwards to it.
  let publicUrl = baseUrl
  if (LIVE) {
    console.log('Opening a Cloudflare quick tunnel (public HTTPS URL for Claude.ai)…')
    tunnel = await startCloudflaredTunnel({ port, log: (m) => console.log(`   • ${m}`) })
    publicUrl = tunnel.url
  }

  const priorRoot = readServeRoot()
  const priorAppDir = priorRoot ? path.join(priorRoot, 'app') : null

  let appDir
  let appEnv
  if (!REUSE || !priorAppDir || !isProvisioned(priorAppDir)) {
    if (priorRoot) rmSync(priorRoot, { recursive: true, force: true })
    const serveRoot = mkdtempSync(path.join(tmpdir(), 'pmoauth-serve-'))
    writeFileSync(SERVE_PTR, serveRoot)
    appDir = path.join(serveRoot, 'app')
    mkdirSync(appDir)
    console.log('Provisioning the test site from the packed plugin (first run is slow — a full install + cold compile)…\n')
    ;({ appEnv } = await provisionApp({ appDir, port, publicUrl, log: (m) => console.log(`   • ${m}`) }))
  } else {
    appDir = priorAppDir
    console.log(`Reusing the existing install at ${appDir} (--reuse). Drop --reuse to rebuild from the freshly packed plugin.`)
    // Re-sync the app source so the reused install reflects current repo source
    // (e.g. the proxy.ts migration) instead of whatever was copied at first
    // provision. Keeps node_modules + the DB, so reuse stays fast.
    refreshAppSource(appDir)
    // Reuse the env from the prior provision so PMOAUTH_TOKEN_PEPPER / PAYLOAD_SECRET
    // stay stable across launches — otherwise OAuth tokens already stored in the
    // persisted DB (hashed with the old pepper) would stop validating. Only the
    // public server URL changes, to match the (possibly new) port or tunnel URL.
    const prior = readEnv(appDir)
    appEnv = prior.PMOAUTH_TOKEN_PEPPER ? { ...prior, NEXT_PUBLIC_SERVER_URL: publicUrl } : makeAppEnv(publicUrl)
    writeEnv(appDir, appEnv)
    await seedAndMigrate(appDir, appEnv)
  }

  // --live: tell Payload to treat the tunnel URL as serverURL + an allowed CSRF
  // origin (see payload.config.ts), so the browser consent POST keeps the session.
  // Only in --live: setting serverURL on plain localhost breaks the origin-less
  // session checks. The OAuth issuer is already the tunnel URL via NEXT_PUBLIC_SERVER_URL.
  if (LIVE) {
    appEnv = { ...appEnv, PMOAUTH_PUBLIC_URL: publicUrl }
    writeEnv(appDir, appEnv)
  }

  // Provisioning is the only thing that can perturb the repo lockfile; the dev
  // server (direct next binary) never touches it. Restore now so the repo is
  // clean for the whole time the server runs, even if it's later SIGKILL'd.
  if (restoreLockfile(lockfileSnapshot)) console.log('Restored repo pnpm-lock.yaml (a pnpm step had modified it).')

  console.log('\nStarting next dev…\n')
  server = startDevServer({ appDir, port, appEnv, inheritStdio: false })
  // Stream next dev's output live (so the slow first compile isn't a silent
  // wait) while still buffering the tail for the crash dump below.
  let log = ''
  server.stdout.on('data', (d) => {
    log += d
    process.stdout.write(d)
  })
  server.stderr.on('data', (d) => {
    log += d
    process.stderr.write(d)
  })
  server.on('close', () => {
    if (!shuttingDown) {
      console.error(`\nnext dev exited unexpectedly:\n${log.slice(-2000)}`)
      shutdown()
    }
  })

  await waitForServer(`${baseUrl}/admin`, 180_000, server)

  // In --live mode the OAuth issuer is the tunnel URL, so discovery + the Claude.ai
  // connector must use it; the admin panel stays on localhost for fast direct access.
  const liveSection = LIVE
    ? `
  🌐  Public URL (Claude.ai Custom Connector):
      ${publicUrl}

  Add it in Claude.ai → Settings → Connectors → Add custom connector,
  then paste the public URL above. Claude discovers the auth server,
  registers itself, and runs the OAuth + PKCE consent flow.
`
    : ''

  console.log(`
────────────────────────────────────────────────────────────
  ✅  Test Payload site is up — installed from the packed plugin.
${liveSection}
  Admin panel : ${baseUrl}/admin
      sign in : ${ADMIN.email}  /  ${ADMIN.password}

  OAuth admin collections (under the "MCP" nav group):
      clients : ${baseUrl}/admin/collections/oauth-clients
      tokens  : ${baseUrl}/admin/collections/oauth-tokens

  OAuth discovery (served via the middleware):
      ${publicUrl}/.well-known/oauth-authorization-server
      ${publicUrl}/.well-known/oauth-protected-resource

  App location: ${appDir}
  Press Ctrl+C to stop${LIVE ? ' (also closes the tunnel)' : ''}.
────────────────────────────────────────────────────────────
`)
  // Idle until Ctrl+C; the detached dev server keeps serving.
} catch (err) {
  console.error(`\nFailed to start the test site: ${err.stack ?? err}`)
  shutdown()
}
