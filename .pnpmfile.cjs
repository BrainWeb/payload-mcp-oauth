'use strict'

// Security overrides: force patched versions for transitive vulnerabilities.
// Remove once upstream packages (payload, @modelcontextprotocol/sdk) pin the
// fixed releases and pnpm-workspace.yaml overrides are honoured by the
// installed pnpm version.
module.exports = {
  hooks: {
    readPackage(pkg) {
      if (pkg.dependencies?.undici) pkg.dependencies.undici = '>=7.28.0 <8'
      if (pkg.dependencies?.hono) pkg.dependencies.hono = '>=4.12.25'
      return pkg
    }
  }
}
