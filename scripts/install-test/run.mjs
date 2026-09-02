#!/usr/bin/env node
// From-scratch packaged install test.
//
// Reproduces installing the PUBLISHED plugin artifact into a fresh Payload app
// and verifies you end up with a working site + working OAuth, asserting hardest
// on the four install pain points: packaging, import map, db migrations, wiring.
// The provisioning (build → pack → install → importmap → migrate) is shared with
// the `serve` command via ./lib/provision.mjs.
//
// Usage:  node scripts/install-test/run.mjs   (or: pnpm test:install)
//         --keep   keep the temp dir even on success (for debugging)

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  ADMIN,
  LOCKFILE,
  freePort,
  provisionApp,
  restoreLockfile,
  run,
  startDevServer,
  waitForServer,
} from './lib/provision.mjs'
import { runHandshake } from './lib/handshake.mjs'
import { runAdminChecks } from './lib/admin-checks.mjs'

const KEEP = process.argv.includes('--keep')
const lockfileSnapshot = readFileSync(LOCKFILE, 'utf8')

// ---- assertion bookkeeping -------------------------------------------------
const checks = []
function check(name, ok, detail = '') {
  checks.push({ name, ok, detail })
  console.log(`  ${ok ? '✓' : '✗'} ${name}${detail && !ok ? `\n      → ${detail}` : ''}`)
}

// ---- main ------------------------------------------------------------------
let tmp
let server
try {
  tmp = mkdtempSync(path.join(tmpdir(), 'pmoauth-install-'))
  const appDir = path.join(tmp, 'app')
  const port = await freePort()

  // 1. Provision the real published artifact into an isolated app.
  console.log('\n[1/7] Provisioning (build → pack → install → importmap → migrate)…')
  const { baseUrl, appEnv, tgzPath, importMapContent, seedResult } = await provisionApp({
    appDir,
    port,
    log: (m) => console.log(`   • ${m}`),
  })
  check('pack: produced a publishable .tgz', !!tgzPath, tgzPath)
  check('install: clean install of the packed tarball (with documented peerDependencyRules) succeeded', true)

  // 2. Packaging: the three published subpaths must resolve through the exports
  //    map to files that exist. We RESOLVE rather than import — /middleware and
  //    /admin pull in next/react, which only resolve inside the bundler, not
  //    under plain Node — so importing them here would be a false negative. We
  //    do import the server-only `.` entry to confirm it executes and exports.
  console.log('\n[2/7] Verifying published entry points resolve…')
  const probe = [
    "import { createRequire } from 'node:module'",
    'const require = createRequire(process.cwd() + "/package.json")',
    "const pkg = '@brainwebuk/payload-plugin-mcp-oauth'",
    "for (const sub of ['', '/middleware', '/admin']) require.resolve(pkg + sub)",
    'const m = await import(pkg)',
    "if (typeof m.payloadMcpOAuth !== 'function') throw new Error('missing payloadMcpOAuth export')",
  ].join(';')
  try {
    await run('node', ['--input-type=module', '-e', probe], { cwd: appDir })
    check('packaging: . , /middleware and /admin subpaths all resolve via exports map', true)
  } catch (err) {
    check('packaging: . , /middleware and /admin subpaths all resolve via exports map', false, String(err.message))
  }

  // 3. Import map: the plugin registers NO custom admin components — the OAuth
  // screens are native collections under the MCP nav group. Guard against a
  // regression that re-introduces the (Payload-v3-incompatible) custom views.
  console.log('\n[3/7] Checking the admin import map…')
  check(
    'importmap: plugin injects no custom admin components (OAuth screens are native collections)',
    !importMapContent.includes('payload-plugin-mcp-oauth/admin'),
    'import map unexpectedly references the plugin /admin subpath — the OAuth admin UI should be native collections, not custom views',
  )

  // 4. DB migrations: the plugin's collections must be queryable.
  console.log('\n[4/7] Checking the OAuth collections (schema push)…')
  check(
    'migrations: oauth-clients / oauth-auth-codes / oauth-tokens are queryable',
    seedResult.ok === true && Object.values(seedResult.collections ?? {}).every(Boolean),
    seedResult.error ?? String(seedResult.raw).slice(-2000),
  )

  // 5. Start the app and drive the full handshake.
  console.log('\n[5/7] Starting the app and running the OAuth + PKCE handshake…')
  server = startDevServer({ appDir, port, appEnv })
  let serverLog = ''
  server.stdout.on('data', (d) => (serverLog += d))
  server.stderr.on('data', (d) => (serverLog += d))
  const beforeHandshake = checks.length
  try {
    await waitForServer(`${baseUrl}/admin`, 180_000, server)
    await runHandshake({ baseUrl, email: ADMIN.email, password: ADMIN.password, check })
  } catch (err) {
    check('handshake: app booted and handshake ran', false, err.message)
  }
  // If anything in the handshake failed, the server log usually explains why
  // (e.g. a config/middleware compile error that 500s every route). Surface it
  // so failures are self-diagnosing rather than needing a manual repro.
  if (checks.slice(beforeHandshake).some((c) => !c.ok)) {
    console.log(`\n--- dev server log tail ---\n${serverLog.slice(-3000)}\n---------------------------`)
  }

  // 6. User-visible admin outcome: an admin can see + open OAuth Clients/Tokens
  //    under the MCP nav group, and the public REST surface stays denied. This is
  //    the assertion the harness lacked when the #33 locked-collection regression
  //    shipped — the import-map check in [3/7] never proved the screens are
  //    reachable. Reuses the still-running server from [5/7].
  console.log('\n[6/7] Checking the OAuth admin collections are visible + access-gated…')
  const beforeAdmin = checks.length
  try {
    await runAdminChecks({ baseUrl, email: ADMIN.email, password: ADMIN.password, check })
  } catch (err) {
    check('admin: OAuth collections visible + gated', false, err.message)
  }
  if (checks.slice(beforeAdmin).some((c) => !c.ok)) {
    console.log(`\n--- dev server log tail ---\n${serverLog.slice(-3000)}\n---------------------------`)
  }

  // The HTTP checks above cover the DEFAULT gate (any user in the admin
  // collection). The security boundary that mattered for the regression is a
  // CUSTOM adminAccess rule that distinguishes admins from other authenticated
  // users — a non-admin must NOT be able to read the OAuth collections. Exercise
  // that via a Local-API fixture (no server) on its own throwaway DB.
  let aaErr = ''
  const aaOut = await run('node', ['--import', 'tsx', 'admin-access-probe.mjs'], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'development', DATABASE_URL: 'file:./admin-access.db' },
  }).catch((e) => ((aaErr = e.message), e.message))
  const aaLine = String(aaOut).split('\n').find((l) => l.includes('ADMIN_ACCESS_RESULT'))
  let aa = {}
  try {
    aa = JSON.parse(aaLine.replace('ADMIN_ACCESS_RESULT', '').trim())
  } catch {
    aa = { ok: false, error: aaErr || String(aaOut).slice(-1500) }
  }
  check('adminAccess: a custom role-based gate allows admins to read the OAuth collections', aa.adminAllowed === true, aa.error ?? `adminAllowed=${aa.adminAllowed}`)
  check('adminAccess: the same gate denies a non-admin (authenticated) user', aa.nonAdminDenied === true, aa.error ?? `nonAdminDenied=${aa.nonAdminDenied}`)

  // 7. Boot matrix: the config must boot cleanly when the plugin is DISABLED
  //    (a no-op that still keeps its collections), and must REFUSE to boot in
  //    production when the env is unsafe. Both are non-server probes of the real
  //    example config via tsx — fast, no dev server.
  console.log('\n[7/7] Verifying boot-time behaviour (disabled no-op boots; production hardening refuses)…')
  const bootProbe = "import('./src/payload.config.ts').then(m=>m.default).then(c=>import('payload').then(p=>p.getPayload({config:c})))"

  // (0) disabled matrix — both disable paths must boot cleanly. mcpPlugin disabled
  //     was the 0.3.3 boot crash (payloadMcpOAuth threw PLUGIN_ORDER because /mcp
  //     wasn't registered). Each runs in dev (so schema push runs) against its own
  //     throwaway DB, so the disabled plugin's kept collections are exercised too.
  for (const [name, extraEnv] of [
    ['payloadMcpOAuth({ disabled: true })', { PMOAUTH_TEST_OAUTH_DISABLED: '1', DATABASE_URL: 'file:./disabled-oauth.db' }],
    ['mcpPlugin disabled (shared mcpOptions)', { PMOAUTH_TEST_MCP_DISABLED: '1', DATABASE_URL: 'file:./disabled-mcp.db' }],
  ]) {
    let bootErr = ''
    await run('node', ['--import', 'tsx', '-e', bootProbe], {
      cwd: appDir,
      env: { ...process.env, ...appEnv, NODE_ENV: 'development', ...extraEnv },
    }).catch((e) => (bootErr = e.message))
    check(`disabled: ${name} boots cleanly (no-op, collections kept)`, !bootErr, bootErr.slice(-1200))
  }

  // (0b) incremental install — adding the plugin to an ALREADY-pushed DB must not
  //      crash. This was 0.3.2: the OAuth collections' FK in payload_locked_
  //      documents_rels forced a rebuild whose INSERT…SELECT referenced not-yet-
  //      existing columns → `no such column: oauth_clients_id`. Boot once with the
  //      plugin OMITTED (pushes a DB without the OAuth collections), then again
  //      WITH it on the SAME db file, which must boot. Fixed via lockDocuments:false.
  const incDb = 'file:./incremental-install.db'
  let incBaseErr = ''
  await run('node', ['--import', 'tsx', '-e', bootProbe], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'development', DATABASE_URL: incDb, PMOAUTH_TEST_OAUTH_OMITTED: '1' },
  }).catch((e) => (incBaseErr = e.message))
  check('incremental: baseline app (plugin omitted) pushes a fresh DB', !incBaseErr, incBaseErr.slice(-1200))
  let incAddErr = ''
  await run('node', ['--import', 'tsx', '-e', bootProbe], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'development', DATABASE_URL: incDb },
  }).catch((e) => (incAddErr = e.message))
  check(
    'incremental: adding the OAuth plugin onto the existing DB boots (no locked-docs rebuild crash)',
    !incAddErr,
    incAddErr ? `second boot failed — a "no such column: oauth_clients_id" here is the 0.3.2 regression:\n${incAddErr.slice(-1500)}` : '',
  )

  // (a) production with a non-https, NON-LOOPBACK issuer must be refused.
  let prodHttpErr = ''
  await run('node', ['--import', 'tsx', '-e', bootProbe], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'production', NEXT_PUBLIC_SERVER_URL: 'http://cms.example.com' },
  }).catch((e) => (prodHttpErr = e.message))
  check(
    'env: NODE_ENV=production with a non-https, non-loopback issuer refuses to boot',
    /https/i.test(prodHttpErr),
    prodHttpErr ? `boot failed but not for https:\n${prodHttpErr.slice(-1200)}` : 'expected a boot failure but it started',
  )
  // (a2) ...but a LOOPBACK http issuer must boot (#71). `next build` sets
  // NODE_ENV=production whether or not you are deploying, so rejecting this made
  // a local production build impossible. appEnv's issuer is http://localhost.
  let prodLoopbackErr = ''
  await run('node', ['--import', 'tsx', '-e', bootProbe], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'production' },
  }).catch((e) => (prodLoopbackErr = e.message))
  check(
    'env: NODE_ENV=production with an http://localhost issuer boots (#71 — local `next build`)',
    !prodLoopbackErr,
    prodLoopbackErr.slice(-1200),
  )
  // (b) production with an https issuer but no pepper must be refused (mentioning the pepper).
  let prodPepperErr = ''
  await run('node', ['--import', 'tsx', '-e', bootProbe], {
    cwd: appDir,
    env: { ...process.env, ...appEnv, NODE_ENV: 'production', NEXT_PUBLIC_SERVER_URL: 'https://localhost', PMOAUTH_TOKEN_PEPPER: '' },
  }).catch((e) => (prodPepperErr = e.message))
  check(
    'env: NODE_ENV=production without PMOAUTH_TOKEN_PEPPER refuses to boot (mentioning the pepper)',
    /pepper|PMOAUTH_TOKEN_PEPPER/i.test(prodPepperErr),
    prodPepperErr ? `boot failed but not for the pepper:\n${prodPepperErr.slice(-1200)}` : 'expected a boot failure but it started',
  )
} catch (err) {
  console.error(`\nInstall test aborted: ${err.stack ?? err}`)
  check('install test ran to completion', false, String(err.message ?? err))
} finally {
  if (server) {
    try {
      process.kill(-server.pid, 'SIGKILL')
    } catch {
      /* already gone */
    }
  }
  if (restoreLockfile(lockfileSnapshot)) {
    console.log('Note: restored repo pnpm-lock.yaml (a pnpm step had modified it).')
  }
  // ---- summary ----
  const failed = checks.filter((c) => !c.ok)
  console.log('\n' + '─'.repeat(60))
  console.log(`Install test: ${checks.length - failed.length}/${checks.length} checks passed`)
  if (failed.length) console.log(`Failed:\n${failed.map((c) => `  ✗ ${c.name}`).join('\n')}`)
  if (tmp && (KEEP || failed.length)) {
    console.log(`\nTemp app kept for debugging: ${path.join(tmp, 'app')}`)
  } else if (tmp) {
    rmSync(tmp, { recursive: true, force: true })
  }
  console.log('─'.repeat(60))
  process.exit(failed.length ? 1 : 0)
}
