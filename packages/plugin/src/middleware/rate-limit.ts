export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
}

export interface RateLimiter {
  check(key: string): boolean
}

interface Bucket {
  count: number
  resetAt: number
}

/**
 * An in-memory fixed-window limiter, scoped to ONE process. Several app
 * instances each keep their own buckets, so the effective ceiling is this limit
 * times the instance count; on serverless a cold start begins with none at all.
 * See the `rateLimits` docs in types.ts — these limits are a speed bump, not the
 * control the flow's security rests on.
 */
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
  const buckets = new Map<string, Bucket>()

  // Evict expired buckets periodically to avoid unbounded growth.
  // We do a lazy sweep on each check rather than a setInterval (no background timer to clean up).
  return {
    check(key: string): boolean {
      const now = Date.now()

      // Lazy eviction: clear expired entries every ~1000 checks
      if (buckets.size > 1000) {
        for (const [k, b] of buckets) {
          if (b.resetAt <= now) buckets.delete(k)
        }
      }

      let bucket = buckets.get(key)
      if (!bucket || bucket.resetAt <= now) {
        bucket = { count: 0, resetAt: now + config.windowMs }
        buckets.set(key, bucket)
      }

      bucket.count += 1
      return bucket.count <= config.maxRequests
    },
  }
}

export interface RateLimitStore {
  register: RateLimiter
  authorize: RateLimiter
  token: RateLimiter
  revoke: RateLimiter
  /** `/oauth/consent` mints authorization codes, so it needs a ceiling too. */
  consent: RateLimiter
}

export interface RateLimitOptions {
  register?: Partial<RateLimitConfig>
  authorize?: Partial<RateLimitConfig>
  token?: Partial<RateLimitConfig>
  revoke?: Partial<RateLimitConfig>
  consent?: Partial<RateLimitConfig>
}

const DEFAULTS: Record<keyof RateLimitStore, RateLimitConfig> = {
  register: { windowMs: 60_000, maxRequests: 10 },
  authorize: { windowMs: 60_000, maxRequests: 60 },
  token: { windowMs: 60_000, maxRequests: 60 },
  revoke: { windowMs: 60_000, maxRequests: 60 },
  consent: { windowMs: 60_000, maxRequests: 30 },
}

export function createRateLimitStore(overrides: RateLimitOptions = {}): RateLimitStore {
  return {
    register: createRateLimiter({ ...DEFAULTS.register, ...overrides.register }),
    authorize: createRateLimiter({ ...DEFAULTS.authorize, ...overrides.authorize }),
    token: createRateLimiter({ ...DEFAULTS.token, ...overrides.token }),
    revoke: createRateLimiter({ ...DEFAULTS.revoke, ...overrides.revoke }),
    consent: createRateLimiter({ ...DEFAULTS.consent, ...overrides.consent }),
  }
}

export function rateLimitKey(ip: string | undefined): string {
  // Key on IP ALONE. Mixing in a client-supplied identifier (client_id /
  // client_name) would give each distinct value its own bucket, so an attacker
  // could rotate that field to mint a fresh quota on every request from the same
  // IP — defeating the per-IP limit entirely. The IP is the one identifier the
  // caller cannot trivially rotate, so it is the correct (and only) key here.
  //
  // Coalesce missing/empty/whitespace IPs to a sentinel: `${'' ?? 'unknown'}`
  // is '' (nullish coalescing does not catch empty strings), which would yield
  // the malformed key `ip:`. Requests with no resolvable IP then share one
  // bucket — unavoidable since they can't be told apart; deployments should sit
  // behind a proxy that always sets x-forwarded-for.
  const id = ip?.trim()
  return `ip:${id || 'unknown'}`
}

export function applyRateLimit(
  limiter: RateLimiter,
  key: string,
  res: { status: (n: number) => { json: (o: unknown) => void }; setHeader: (k: string, v: string) => void },
): boolean {
  if (!limiter.check(key)) {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Retry-After', '60')
    res.status(429).json({ error: 'too_many_requests', error_description: 'Rate limit exceeded' })
    return false
  }
  return true
}
