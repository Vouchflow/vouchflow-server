// Read-scoped customer stats and verification listing for the dashboard.
// Both endpoints require a vsk_*_read or vsk_*_write key (sandbox or live)
// — the existing apiKeyAuth plugin scopes each route. Write keys can read
// too (they're a strict superset), so the dashboard's sandbox-write-key
// session works without changes.

import { FastifyPluginAsync } from 'fastify'
import { z } from 'zod'
import { prisma } from '../lib/prisma.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'

const RANGE_DAYS: Record<string, number> = { '1d': 1, '7d': 7, '30d': 30, '90d': 90 }

// Dashboard env toggle. Filters Device/Verification rows on is_sandbox.
// Defaults to 'sandbox' since dashboard sessions start in sandbox mode and
// the sandbox/live data sets are completely disjoint — there's no useful
// "show both" view.
const EnvFilter = z.enum(['sandbox', 'production']).optional().default('sandbox')

const StatsQuery = z.object({
  range: z.enum(['1d', '7d', '30d', '90d']).optional().default('7d'),
  env:   EnvFilter,
})

// Result classifier for the dashboard's third filter dropdown:
//   verified — terminal success at the high confidence ceiling
//   degraded — terminal success at medium/low confidence
//   failed   — any terminal failure path (auth failed, expired, OTP locked)
// Independent of the confidence filter — the two AND together so a user
// can ask for 'failed at medium confidence' if that ever matters.
const VerificationsQuery = z.object({
  limit:      z.coerce.number().int().min(1).max(100).optional().default(20),
  offset:     z.coerce.number().int().min(0).optional().default(0),
  confidence: z.enum(['high', 'medium', 'low']).optional(),
  platform:   z.enum(['ios', 'android', 'web']).optional(),
  range:      z.enum(['1d', '7d', '30d', '90d']).optional(),
  result:     z.enum(['verified', 'degraded', 'failed']).optional(),
  env:        EnvFilter,
})

const route: FastifyPluginAsync = async (fastify) => {
  // Read-scope is the floor. apiKeyAuth treats write keys as satisfying read
  // checks too, so the dashboard's sandbox-write key works on these.
  await fastify.register(makeApiKeyAuthPlugin('read'))

  // GET /v1/customers/:id/stats?range=7d
  // Returns the headline numbers the dashboard renders + a daily breakdown
  // for the chart. Scoped to the auth'd customer; ignores the :id param's
  // value (uses request.customerId from auth) so a leaked URL can't read
  // another customer's stats.
  fastify.get<{ Querystring: { range?: string; env?: string } }>(
    '/customers/:id/stats',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
      schema: { querystring: { type: 'object', properties: { range: { type: 'string' }, env: { type: 'string' } } } },
    },
    async (request, reply) => {
      const parsed = StatsQuery.safeParse(request.query)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const { range, env } = parsed.data
      const days = RANGE_DAYS[range]
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      const customerId = request.customerId
      const isSandbox = env === 'sandbox'

      // Terminal states that count as a "success" (user got through) vs a
      // "failure" (a real attempt that didn't succeed). INITIATED and FALLBACK
      // are in-flight and not counted in the rate.
      const SUCCESS_STATES = ['COMPLETED', 'FALLBACK_COMPLETE'] as const
      const FAILURE_STATES = ['FAILED', 'EXPIRED', 'FALLBACK_LOCKED', 'FALLBACK_EXPIRED'] as const

      const [
        verificationCount,
        deviceRows,
        confidenceBreakdown,
        successCount,
        failureCount,
        dailyRows,
      ] = await Promise.all([
        prisma.verification.count({
          where: { customerId, isSandbox, createdAt: { gte: since }, state: { in: [...SUCCESS_STATES] } },
        }),
        // Active devices enrolled within the selected window, deduped by
        // keyFingerprint. The enroll route upserts on deviceToken, so app
        // reinstalls or test runs that don't send a stable token mint a new
        // row each time, inflating the count. The attestation key is more
        // durable than the token, so distinct fingerprints is closer to
        // "physical devices we've seen."
        prisma.device.findMany({
          where:    { customerId, isSandbox, status: 'active', enrolledAt: { gte: since } },
          select:   { keyFingerprint: true },
          distinct: ['keyFingerprint'],
        }),
        // Confidence breakdown for the percentage card.
        prisma.verification.groupBy({
          by: ['confidence'],
          where: { customerId, isSandbox, createdAt: { gte: since }, confidence: { not: null } },
          _count: { _all: true },
        }),
        // Success/failure counts back the success-rate card. Counted across
        // all attempts that reached a terminal state in the window.
        prisma.verification.count({
          where: { customerId, isSandbox, createdAt: { gte: since }, state: { in: [...SUCCESS_STATES] } },
        }),
        prisma.verification.count({
          where: { customerId, isSandbox, createdAt: { gte: since }, state: { in: [...FAILURE_STATES] } },
        }),
        // Daily breakdown for the chart.
        prisma.$queryRaw<Array<{ d: Date; high: bigint; low: bigint }>>`
          SELECT
            DATE_TRUNC('day', created_at) AS d,
            SUM(CASE WHEN confidence = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN confidence IN ('medium', 'low') THEN 1 ELSE 0 END) AS low
          FROM verifications
          WHERE customer_id = ${customerId}
            AND is_sandbox = ${isSandbox}
            AND created_at >= ${since}
            AND state IN ('COMPLETED', 'FALLBACK_COMPLETE')
          GROUP BY d
          ORDER BY d ASC
        `,
      ])

      const totalConfidence = confidenceBreakdown.reduce((acc, r) => acc + r._count._all, 0)
      const high = confidenceBreakdown.find(r => r.confidence === 'high')?._count._all ?? 0
      const highConfidencePct = totalConfidence === 0 ? null : (high / totalConfidence) * 100

      const totalAttempts = successCount + failureCount
      const successRatePct = totalAttempts === 0 ? null : (successCount / totalAttempts) * 100

      return reply.send({
        verificationCount,
        deviceCount: deviceRows.length,
        highConfidencePct,
        successRatePct,
        dailyBreakdown: dailyRows.map(row => ({
          date: row.d.toISOString().slice(0, 10),
          high: Number(row.high),
          low:  Number(row.low),
        })),
      })
    },
  )

  // GET /v1/verifications
  // Paginated list of recent verifications. The `:id` from the URL is not
  // used — scope comes from request.customerId. Filters: confidence,
  // platform (joined via device).
  fastify.get<{ Querystring: { limit?: string; offset?: string; confidence?: string; platform?: string; env?: string } }>(
    '/verifications',
    {
      config: { rateLimit: { max: 100, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const parsed = VerificationsQuery.safeParse(request.query)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const { limit, offset, confidence, platform, range, result, env } = parsed.data
      const isSandbox = env === 'sandbox'
      const since = range ? new Date(Date.now() - RANGE_DAYS[range] * 24 * 60 * 60 * 1000) : undefined

      // result narrows the candidate states + (for verified/degraded) confidence.
      // No filter → any terminal state, any confidence.
      let resultStateFilter: Record<string, unknown> = { state: { in: ['COMPLETED', 'FALLBACK_COMPLETE', 'FAILED', 'EXPIRED', 'FALLBACK_LOCKED', 'FALLBACK_EXPIRED'] } }
      if (result === 'verified') {
        resultStateFilter = { state: { in: ['COMPLETED', 'FALLBACK_COMPLETE'] }, confidence: 'high' }
      } else if (result === 'degraded') {
        resultStateFilter = { state: { in: ['COMPLETED', 'FALLBACK_COMPLETE'] }, confidence: { in: ['medium', 'low'] } }
      } else if (result === 'failed') {
        resultStateFilter = { state: { in: ['FAILED', 'EXPIRED', 'FALLBACK_LOCKED', 'FALLBACK_EXPIRED'] } }
      }

      const rows = await prisma.verification.findMany({
        where: {
          customerId: request.customerId,
          isSandbox,
          ...resultStateFilter,
          ...(since      ? { createdAt: { gte: since } } : {}),
          ...(confidence ? { confidence } : {}),
          ...(platform   ? { device: { platform } } : {}),
        },
        include: { device: { select: { platform: true, deviceToken: true } } },
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: limit,
      })

      return reply.send({
        rows: rows.map(v => ({
          sessionId:   v.sessionId,
          deviceToken: v.device?.deviceToken ?? null,
          confidence:  v.confidence ?? 'low',
          platform:    v.device?.platform ?? 'unknown',
          biometric:   v.biometricUsed === true ? 'biometric' : (v.fallbackUsed ? 'fallback' : 'none'),
          durationMs:  v.completedAt ? v.completedAt.getTime() - v.createdAt.getTime() : null,
          createdAt:   v.createdAt.toISOString(),
        })),
      })
    },
  )

  // GET /v1/verifications/:sessionId
  fastify.get<{ Params: { sessionId: string } }>(
    '/verifications/:sessionId',
    {
      config: { rateLimit: { max: 100, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const v = await prisma.verification.findFirst({
        where: { sessionId: request.params.sessionId, customerId: request.customerId },
        include: { device: { select: { platform: true, deviceToken: true } } },
      })
      if (!v) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Verification not found.' } })
      }
      return reply.send({
        sessionId:   v.sessionId,
        deviceToken: v.device?.deviceToken ?? null,
        confidence:  v.confidence ?? 'low',
        platform:    v.device?.platform ?? 'unknown',
        biometric:   v.biometricUsed === true ? 'biometric' : (v.fallbackUsed ? 'fallback' : 'none'),
        durationMs:  v.completedAt ? v.completedAt.getTime() - v.createdAt.getTime() : null,
        createdAt:   v.createdAt.toISOString(),
      })
    },
  )
}

export default route
