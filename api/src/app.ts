import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import { redis } from './lib/redis.js'
import responseHeaders from './plugins/responseHeaders.js'
import enrollRoute from './routes/enroll.js'
import verifyRoute from './routes/verify.js'
import deviceRoute from './routes/device.js'
import customerRoute from './routes/customers.js'
import statsRoute from './routes/stats.js'
import webhookRoute from './routes/webhooks.js'

export async function buildApp() {
  const fastify = Fastify({
    logger: true,
    // Expose request.ip correctly behind Caddy
    trustProxy: true,
  })

  // ── Plugins ────────────────────────────────────────────────────────────────
  await fastify.register(responseHeaders)

  // §7 Per-endpoint rate limits: configured on each route using the
  // @fastify/rate-limit plugin. Global registration required first.
  // keyGenerator uses IP — customerId is not available at onRequest (before auth).
  // Per-route limits further scope by endpoint URL.
  await fastify.register(rateLimit, {
    redis,
    max: 1000,
    timeWindow: '1 minute',
    keyGenerator: (request) => `${request.ip}:${request.routeOptions.url}`,
  })

  // ── Routes ─────────────────────────────────────────────────────────────────
  await fastify.register(enrollRoute,  { prefix: '/v1' })
  await fastify.register(verifyRoute,  { prefix: '/v1' })
  await fastify.register(deviceRoute,  { prefix: '/v1' })
  await fastify.register(customerRoute, { prefix: '/v1' })
  await fastify.register(statsRoute,    { prefix: '/v1' })
  await fastify.register(webhookRoute,  { prefix: '/v1' })

  // ── Health ─────────────────────────────────────────────────────────────────
  // Exempt from rate limiting — rate limiter uses Redis, which may be
  // temporarily unavailable. Health must respond independently.
  fastify.get('/health', { config: { rateLimit: false } }, async () => ({ status: 'ok' }))

  return fastify
}
