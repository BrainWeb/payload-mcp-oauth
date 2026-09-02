import crypto from 'crypto'

const DEV_PEPPER = 'dev-insecure-pepper-do-not-use-in-production-0000000'

function getPepper(): string {
  const pepper = process.env['PMOAUTH_TOKEN_PEPPER']
  if (pepper && pepper.length >= 32) return pepper
  // The insecure built-in fallback is ONLY for explicit development/test. Any
  // other environment (production, staging, or NODE_ENV unset) MUST provide a
  // real pepper — otherwise token hashes would be forgeable with the public
  // DEV_PEPPER baked into the published package.
  const nodeEnv = process.env['NODE_ENV']
  if (nodeEnv === 'development' || nodeEnv === 'test') return DEV_PEPPER
  throw new Error(
    '[payload-plugin-mcp-oauth] PMOAUTH_TOKEN_PEPPER is missing or too short. ' +
      'It must be at least 32 characters outside of NODE_ENV=development|test. ' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
  )
}

export function hashToken(plaintext: string): string {
  return crypto.createHmac('sha256', getPepper()).update(plaintext).digest('hex')
}

/**
 * Constant-time comparison of a token against a stored hash.
 *
 * Not used by the current flows — every lookup is an indexed query on the hash
 * itself, which never compares secrets in application code. Kept as the correct
 * primitive for any future path that does hold both values (e.g. verifying a
 * token against a row already in hand), so that path does not reach for `===`.
 */
export function compareTokenHash(plaintext: string, storedHash: string): boolean {
  const computed = Buffer.from(hashToken(plaintext), 'hex')
  const stored = Buffer.from(storedHash, 'hex')

  // Lengths should always be equal (both are SHA-256 hex = 64 chars / 32 bytes),
  // but guard against malformed stored values without leaking timing.
  if (computed.length !== stored.length) {
    crypto.timingSafeEqual(computed, computed)
    return false
  }

  return crypto.timingSafeEqual(computed, stored)
}
