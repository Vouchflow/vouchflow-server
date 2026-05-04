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

const StatsQuery = z.object({
  range: z.enum(['1d', '7d', '30d', '90d']).optional().default('7d'),
})

const VerificationsQuery = z.object({
  limit:      z.coerce.number().int().min(1).max(100).optional().default(20),
  offset:     z.coerce.number().int().min(0).optional().default(0),
  confidence: z.enum(['high', 'medium', 'low']).optional(),
  platform:   z.enum(['ios', 'android', 'web']).optional(),
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
  fastify.get<{ Querystring: { range?: string } }>(
    '/customers/:id/stats',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
      schema: { querystring: { type: 'object', properties: { range: { type: 'string' } } } },
    },
    async (request, reply) => {
      const parsed = StatsQuery.safeParse(request.query)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const { range } = parsed.data
      const days = RANGE_DAYS[range]
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      const customerId = request.customerId

      const [
        verificationCount,
        deviceRows,
        confidenceBreakdown,
        durationRows,
        dailyRows,
      ] = await Promise.all([
        prisma.verification.count({
          where: { customerId, createdAt: { gte: since }, state: { in: ['COMPLETED', 'FALLBACK_COMPLETE'] } },
        }),
        // Active devices, deduped by keyFingerprint. The enroll route upserts
        // on deviceToken, so app reinstalls or test runs that don't send a
        // stable token mint a new row each time, inflating the count. The
        // attestation key is more durable than the token, so distinct
        // fingerprints is closer to "physical devices we've seen."
        prisma.device.findMany({
          where:    { customerId, status: 'active' },
          select:   { keyFingerprint: true },
          distinct: ['keyFingerprint'],
        }),
        // Confidence breakdown for the percentage card.
        prisma.verification.groupBy({
          by: ['confidence'],
          where: { customerId, createdAt: { gte: since }, confidence: { not: null } },
          _count: { _all: true },
        }),
        // Average completion latency for the duration card. Uses raw SQL
        // because Prisma's groupBy doesn't expose avg over an interval
        // expression cleanly.
        prisma.$queryRaw<Array<{ avg_ms: number | null }>>`
          SELECT AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) * 1000) AS avg_ms
          FROM verifications
          WHERE customer_id = ${customerId}
            AND created_at >= ${since}
            AND completed_at IS NOT NULL
            AND state IN ('COMPLETED', 'FALLBACK_COMPLETE')
        `,
        // Daily breakdown for the chart.
        prisma.$queryRaw<Array<{ d: Date; high: bigint; low: bigint }>>`
          SELECT
            DATE_TRUNC('day', created_at) AS d,
            SUM(CASE WHEN confidence = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN confidence IN ('medium', 'low') THEN 1 ELSE 0 END) AS low
          FROM verifications
          WHERE customer_id = ${customerId}
            AND created_at >= ${since}
            AND state IN ('COMPLETED', 'FALLBACK_COMPLETE')
          GROUP BY d
          ORDER BY d ASC
        `,
      ])

      const totalConfidence = confidenceBreakdown.reduce((acc, r) => acc + r._count._all, 0)
      const high = confidenceBreakdown.find(r => r.confidence === 'high')?._count._all ?? 0
      const highConfidencePct = totalConfidence === 0 ? null : (high / totalConfidence) * 100

      return reply.send({
        verificationCount,
        deviceCount: deviceRows.length,
        highConfidencePct,
        avgDurationMs: durationRows[0]?.avg_ms ?? null,
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
  fastify.get<{ Querystring: { limit?: string; offset?: string; confidence?: string; platform?: string } }>(
    '/verifications',
    {
      config: { rateLimit: { max: 100, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const parsed = VerificationsQuery.safeParse(request.query)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const { limit, offset, confidence, platform } = parsed.data

      const rows = await prisma.verification.findMany({
        where: {
          customerId: request.customerId,
          state: { in: ['COMPLETED', 'FALLBACK_COMPLETE', 'FAILED'] },
          ...(confidence ? { confidence } : {}),
          ...(platform   ? { device: { platform } } : {}),
        },
        include: { device: { select: { platform: true } } },
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: limit,
      })

      return reply.send({
        rows: rows.map(v => ({
          sessionId:  v.sessionId,
          confidence: v.confidence ?? 'low',
          platform:   v.device?.platform ?? 'unknown',
          biometric:  v.biometricUsed === true ? 'biometric' : (v.fallbackUsed ? 'fallback' : 'none'),
          durationMs: v.completedAt ? v.completedAt.getTime() - v.createdAt.getTime() : null,
          createdAt:  v.createdAt.toISOString(),
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
        include: { device: { select: { platform: true } } },
      })
      if (!v) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Verification not found.' } })
      }
      return reply.send({
        sessionId:  v.sessionId,
        confidence: v.confidence ?? 'low',
        platform:   v.device?.platform ?? 'unknown',
        biometric:  v.biometricUsed === true ? 'biometric' : (v.fallbackUsed ? 'fallback' : 'none'),
        durationMs: v.completedAt ? v.completedAt.getTime() - v.createdAt.getTime() : null,
        createdAt:  v.createdAt.toISOString(),
      })
    },
  )
}

export default route
