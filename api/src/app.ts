import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import cors from '@fastify/cors'
import responseHeaders from './plugins/responseHeaders.js'
import enrollRoute from './routes/enroll.js'
import verifyRoute from './routes/verify.js'
import signRoute from './routes/sign.js'
import jwksRoute from './routes/jwks.js'
import deviceRoute from './routes/device.js'
import customerRoute from './routes/customers.js'
import appsRoute from './routes/apps.js'
import statsRoute from './routes/stats.js'
import webhookRoute from './routes/webhooks.js'

export async function buildApp() {
  const fastify = Fastify({
    logger: true,
    // Expose request.ip correctly behind Caddy
    trustProxy: true,
  })

  // ── Plugins ────────────────────────────────────────────────────────────────
  // CORS: the Web SDK runs at the customer's origin (e.g. app.trustysquire.ai)
  // and talks to api.vouchflow.dev. Browsers preflight every cross-origin POST,
  // and Authorization is a non-simple header, so without this every Web SDK
  // request would fail at OPTIONS. Origin reflection is safe here — the API
  // is authenticated by API key, not by origin or cookie. Credentialed mode is
  // explicitly disabled.
  await fastify.register(cors, {
    origin: true,
    credentials: false,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['authorization', 'content-type', 'vouchflow-api-version', 'idempotency-key'],
    maxAge: 86400,
  })

  await fastify.register(responseHeaders)

  // §7 Per-endpoint rate limits: configured on each route using the
  // @fastify/rate-limit plugin. Global registration required first.
  // keyGenerator uses IP — customerId is not available at onRequest (before auth).
  // Per-route limits further scope by endpoint URL.
  //
  // Storage: in-process Map (the default when no `redis` is passed). With one
  // API machine, the Redis-backed store was paying per-request Upstash
  // commands for what amounts to a hash table — and ~90% of that traffic was
  // scanner noise (/wp-admin, /.well-known, /sites/default/files…) returning
  // 404. In-memory is correct here; if we ever scale to multiple API machines
  // we revisit per-machine vs per-tenant limits separately.
  await fastify.register(rateLimit, {
    max: 1000,
    timeWindow: '1 minute',
    keyGenerator: (request) => `${request.ip}:${request.routeOptions.url}`,
  })

  // ── Routes ─────────────────────────────────────────────────────────────────
  await fastify.register(enrollRoute,  { prefix: '/v1' })
  await fastify.register(verifyRoute,  { prefix: '/v1' })
  await fastify.register(signRoute,    { prefix: '/v1' })
  await fastify.register(jwksRoute)    // No prefix — /.well-known/jwks.json is a standard location
  await fastify.register(deviceRoute,  { prefix: '/v1' })
  await fastify.register(customerRoute, { prefix: '/v1' })
  await fastify.register(appsRoute,     { prefix: '/v1' })
  await fastify.register(statsRoute,    { prefix: '/v1' })
  await fastify.register(webhookRoute,  { prefix: '/v1' })

  // ── Health ─────────────────────────────────────────────────────────────────
  // Exempt from rate limiting — rate limiter uses Redis, which may be
  // temporarily unavailable. Health must respond independently.
  fastify.get('/health', { config: { rateLimit: false } }, async () => ({ status: 'ok' }))

  return fastify
}
