import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import cookie from '@fastify/cookie'
import session from '@fastify/session'
import staticFiles from '@fastify/static'
import path from 'path'
import { redis } from './lib/redis.js'
import { config } from './config.js'
import responseHeaders from './plugins/responseHeaders.js'
import enrollRoute from './routes/enroll.js'
import verifyRoute from './routes/verify.js'
import deviceRoute from './routes/device.js'
import authRoutes from './routes/auth.js'
import pageRoutes from './routes/pages.js'
import webRoutes from './routes/web.js'

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

  // ── Session ────────────────────────────────────────────────────────────────
  // cookie must be registered before session
  await fastify.register(cookie)
  await fastify.register(session, {
    secret: config.sessionSecret,
    cookie: {
      secure: config.nodeEnv === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
    saveUninitialized: false,
  })

  // ── Static files ────────────────────────────────────────────────────────────
  // Register after session, before page routes.
  // index: false — pages.ts handles routing explicitly.
  await fastify.register(staticFiles, {
    // process.cwd() == api/ in local dev (npm run dev), /app in production (Docker WORKDIR)
    root: path.join(process.cwd(), 'public'),
    prefix: '/',
    index: false,
  })

  // ── Routes ─────────────────────────────────────────────────────────────────
  await fastify.register(enrollRoute, { prefix: '/v1' })
  await fastify.register(verifyRoute, { prefix: '/v1' })
  await fastify.register(deviceRoute, { prefix: '/v1' })
  await fastify.register(authRoutes)
  await fastify.register(pageRoutes)
  await fastify.register(webRoutes)

  // ── Health ─────────────────────────────────────────────────────────────────
  // Exempt from rate limiting — rate limiter uses Redis, which may be
  // temporarily unavailable. Health must respond independently.
  fastify.get('/health', { config: { rateLimit: false } }, async () => ({ status: 'ok' }))

  return fastify
}
