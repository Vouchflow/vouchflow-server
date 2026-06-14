// Tiny in-process counter-with-TTL, dropped in to replace the Redis INCR+EXPIRE
// pattern previously used by verify.ts for per-IP + per-email rate limiting.
//
// One API machine = correct scope: rate limits are per-machine, not per-tenant,
// and we explicitly accepted that trade-off when we moved @fastify/rate-limit
// off Redis earlier. This module is the same pattern for the route-internal
// counters that didn't go through that plugin.
//
// Memory is bounded by the eager-expiry on read + the hourly reaper below.
// At our verify volume (single digits/minute even under load) the map size
// stays in the hundreds. Each entry is ~64 bytes; ten thousand entries =
// 640KB, well under any realistic budget.

type Counter = { count: number; expiresAt: number }

const counters = new Map<string, Counter>()

/**
 * Increment a counter under `key` and (re)set its TTL on first hit.
 * Returns the post-increment value, matching Redis INCR semantics.
 *
 * - First call (or call after expiry): returns 1, TTL starts now.
 * - Subsequent calls within TTL: increment, TTL is NOT extended (matches the
 *   original `if (count === 1) await redis.expire(...)` pattern in verify.ts).
 */
export function counterIncr(key: string, ttlSeconds: number): number {
  const now = Date.now()
  const existing = counters.get(key)
  if (existing && existing.expiresAt > now) {
    existing.count += 1
    return existing.count
  }
  // First hit (or expired): re-seed with TTL.
  counters.set(key, { count: 1, expiresAt: now + ttlSeconds * 1000 })
  return 1
}

// Hourly sweep of expired entries so abandoned keys (unique IPs, one-off
// emails) don't pile up. Linear scan over the Map; at our cardinality
// (low thousands) this is microseconds.
setInterval(() => {
  const now = Date.now()
  for (const [key, row] of counters) {
    if (row.expiresAt <= now) counters.delete(key)
  }
}, 60 * 60 * 1000).unref()
