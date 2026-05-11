import type { FastifyInstance } from 'fastify'
import { prisma } from '../lib/prisma.js'
import crypto from 'node:crypto'
import { verifyAdminKey } from '../lib/adminAuth.js'

export default async function customerRoute(fastify: FastifyInstance) {

  // POST /v1/customers
  // Find or create a customer by email. Authenticated with ADMIN_KEY.
  // Called by the web app on every magic link verification.
  fastify.post<{ Body: { email: string } }>(
    '/customers',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: { email: { type: 'string', format: 'email' } },
        },
      },
    },
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const email = request.body.email.toLowerCase().trim()

      let customer = await prisma.customer.findUnique({
        where: { email },
        include: { apps: { where: { archivedAt: null }, orderBy: { createdAt: 'asc' }, take: 1 } },
      })

      // chunk1-compile-fix: sandbox keys live on App after the apps refactor.
      // POST /v1/customers now also creates a default App when a new customer
      // signs up. Chunk 2 reshapes this into the explicit App-creation flow,
      // but for compile-correctness we co-create the App here.
      if (!customer) {
        const sandboxWriteKey = `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`
        const sandboxReadKey  = `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`
        const created = await prisma.customer.create({
          data: {
            email,
            webhookSecret: `whsec_${crypto.randomBytes(20).toString('hex')}`,
            apps: {
              create: {
                name: 'Default App',
                slug: 'default',
                sandboxWriteKey,
                sandboxReadKey,
                signPayloadMinConfidence: 'high',
              },
            },
          },
          include: { apps: { where: { archivedAt: null }, orderBy: { createdAt: 'asc' }, take: 1 } },
        })
        customer = created
      }

      const defaultApp = customer.apps[0]

      return reply.send({
        id:              customer.id,
        email:           customer.email,
        sandboxWriteKey: defaultApp?.sandboxWriteKey ?? null,
        sandboxReadKey:  defaultApp?.sandboxReadKey ?? null,
        webhookSecret:   customer.webhookSecret,
        createdAt:       customer.createdAt,
      })
    }
  )

  // GET /v1/customers/:id/overview
  // Admin-keyed customer-wide aggregation across all the customer's
  // non-archived apps. The dashboard's account-level overview view calls
  // this. Per-app stats live at /v1/customers/:id/stats (SDK-key auth) —
  // the admin path is separate to avoid an auth-mode branch on a single URL.
  fastify.get<{
    Params: { id: string }
    Querystring: { range?: string; env?: string }
  }>(
    '/customers/:id/overview',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const range = request.query.range ?? '7d'
      const days = ({ '1d': 1, '7d': 7, '30d': 30, '90d': 90, '24h': 1 } as Record<string, number>)[range]
      if (days === undefined) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: 'range must be 1d|7d|30d|90d.' } })
      }
      const isSandbox = request.query.env !== 'production'
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      const customerId = request.params.id

      const SUCCESS_STATES = ['COMPLETED', 'FALLBACK_COMPLETE']
      const FAILURE_STATES = ['FAILED', 'EXPIRED', 'FALLBACK_LOCKED', 'FALLBACK_EXPIRED']

      // Aggregate across all of the customer's non-archived apps. Archived
      // apps are excluded so the overview reflects production reality, not
      // historical data the customer has explicitly retired.
      const activeAppIds = (await prisma.app.findMany({
        where: { customerId, archivedAt: null },
        select: { id: true },
      })).map(a => a.id)

      if (activeAppIds.length === 0) {
        return reply.send({
          appCount: 0,
          verificationCount: 0,
          deviceCount: 0,
          successRatePct: null,
          highConfidencePct: null,
          perApp: [],
        })
      }

      const [verificationCount, deviceRows, successCount, failureCount, confidenceBreakdown, perApp] = await Promise.all([
        prisma.verification.count({
          where: { appId: { in: activeAppIds }, isSandbox, createdAt: { gte: since }, state: { in: SUCCESS_STATES } },
        }),
        prisma.device.findMany({
          where: { appId: { in: activeAppIds }, isSandbox, status: 'active', enrolledAt: { gte: since } },
          select: { keyFingerprint: true },
          distinct: ['keyFingerprint'],
        }),
        prisma.verification.count({
          where: { appId: { in: activeAppIds }, isSandbox, createdAt: { gte: since }, state: { in: SUCCESS_STATES } },
        }),
        prisma.verification.count({
          where: { appId: { in: activeAppIds }, isSandbox, createdAt: { gte: since }, state: { in: FAILURE_STATES } },
        }),
        prisma.verification.groupBy({
          by: ['confidence'],
          where: { appId: { in: activeAppIds }, isSandbox, createdAt: { gte: since }, confidence: { not: null } },
          _count: { _all: true },
        }),
        prisma.verification.groupBy({
          by: ['appId'],
          where: { appId: { in: activeAppIds }, isSandbox, createdAt: { gte: since }, state: { in: SUCCESS_STATES } },
          _count: { _all: true },
        }),
      ])

      const totalConfidence = confidenceBreakdown.reduce((acc, r) => acc + r._count._all, 0)
      const high = confidenceBreakdown.find(r => r.confidence === 'high')?._count._all ?? 0
      const highConfidencePct = totalConfidence === 0 ? null : (high / totalConfidence) * 100
      const totalAttempts = successCount + failureCount
      const successRatePct = totalAttempts === 0 ? null : (successCount / totalAttempts) * 100

      return reply.send({
        appCount: activeAppIds.length,
        verificationCount,
        deviceCount: deviceRows.length,
        successRatePct,
        highConfidencePct,
        perApp: perApp.map(r => ({ appId: r.appId, verificationCount: r._count._all })),
      })
    }
  )

  // ── Customer-scoped live-keys: deprecation shim ────────────────────────
  //
  // Live keys moved to App scope (POST /v1/customers/:id/apps/:appId/live-keys
  // in apps.ts). These customer-scoped endpoints stay as transitional shims
  // for callers that hardcoded the old paths:
  //   - exactly one non-archived app  → 308 redirect to the app's endpoint,
  //     plus a `Vouchflow-Deprecation` header
  //   - 0 or 2+ non-archived apps     → 409 ambiguous_app (caller must pick)
  // The shim does not create or modify keys directly anymore.

  async function resolveSingleApp(customerId: string) {
    return prisma.app.findMany({
      where: { customerId, archivedAt: null },
      orderBy: { createdAt: 'asc' },
      select: { id: true, name: true, slug: true },
    })
  }

  function ambiguous(reply: any, apps: { id: string; name: string }[]) {
    return reply.code(409).send({
      error: {
        code: 'ambiguous_app',
        message: 'Customer has multiple apps. Use the app-scoped endpoint.',
      },
      apps: apps.map(a => ({ id: a.id, name: a.name })),
    })
  }

  // POST /v1/customers/:id/live-keys — shim → POST /apps/:appId/live-keys
  fastify.post<{ Params: { id: string }; Body: { scope?: 'pair' | 'write' | 'read' } }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const apps = await resolveSingleApp(request.params.id)
      if (apps.length === 0) {
        return reply.code(409).send({ error: { code: 'no_app', message: 'Customer has no active apps.' } })
      }
      if (apps.length > 1) return ambiguous(reply, apps)
      reply.header('Vouchflow-Deprecation', 'customer-scoped-live-keys')
      return reply
        .code(308)
        .header('Location', `/v1/customers/${request.params.id}/apps/${apps[0].id}/live-keys`)
        .send({ error: { code: 'moved', message: 'Endpoint moved to app scope.' } })
    }
  )

  // GET /v1/customers/:id/live-keys — shim → GET /apps/:appId/live-keys
  fastify.get<{ Params: { id: string } }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const apps = await resolveSingleApp(request.params.id)
      if (apps.length === 0) {
        return reply.code(409).send({ error: { code: 'no_app', message: 'Customer has no active apps.' } })
      }
      if (apps.length > 1) return ambiguous(reply, apps)
      reply.header('Vouchflow-Deprecation', 'customer-scoped-live-keys')
      return reply
        .code(308)
        .header('Location', `/v1/customers/${request.params.id}/apps/${apps[0].id}/live-keys`)
        .send({ error: { code: 'moved', message: 'Endpoint moved to app scope.' } })
    }
  )

  // DELETE /v1/customers/:id/live-keys/:keyId — shim. We can resolve the key's
  // appId directly, so the redirect is unambiguous regardless of app count.
  fastify.delete<{ Params: { id: string; keyId: string } }>(
    '/customers/:id/live-keys/:keyId',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const key = await prisma.apiKey.findFirst({
        where: { id: request.params.keyId, customerId: request.params.id },
        select: { appId: true },
      })
      if (!key) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Key not found.' } })
      }
      reply.header('Vouchflow-Deprecation', 'customer-scoped-live-keys')
      return reply
        .code(308)
        .header('Location', `/v1/customers/${request.params.id}/apps/${key.appId}/live-keys/${request.params.keyId}`)
        .send({ error: { code: 'moved', message: 'Endpoint moved to app scope.' } })
    }
  )

  // DELETE /v1/customers/:id
  // Permanently delete a customer and all associated data. Authenticated with ADMIN_KEY.
  fastify.delete<{ Params: { id: string } }>(
    '/customers/:id',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const { id: customerId } = request.params

      await prisma.$transaction(async (tx) => {
        // Webhook deliveries reference endpoints — delete first
        const endpoints = await tx.webhookEndpoint.findMany({
          where: { customerId }, select: { id: true },
        })
        if (endpoints.length > 0) {
          await tx.webhookDelivery.deleteMany({
            where: { endpointId: { in: endpoints.map(e => e.id) } },
          })
        }
        await tx.webhookEndpoint.deleteMany({ where: { customerId } })
        // Verifications reference devices — delete verifications first
        await tx.verification.deleteMany({ where: { customerId } })
        await tx.device.deleteMany({ where: { customerId } })
        await tx.apiKey.deleteMany({ where: { customerId } })
        await tx.customer.delete({ where: { id: customerId } })
      })

      return reply.send({ ok: true })
    }
  )

  // PATCH /v1/customers/:id
  // Update mutable customer fields. Authenticated with ADMIN_KEY.
  //
  // chunk1-compile-fix: the four attestation fields used to live on Customer;
  // they moved to App in the apps refactor. Chunk 2 introduces the per-app
  // PATCH endpoint that owns those validators. This handler only accepts
  // customer-level fields now.
  fastify.patch<{
    Params: { id: string }
    Body: {
      orgName?: string
      billingEmail?: string
      minimumConfidence?: string
      networkOptIn?: boolean
    }
  }>(
    '/customers/:id',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const { orgName, billingEmail, minimumConfidence, networkOptIn } = request.body

      const data: Record<string, unknown> = {}
      if (orgName           !== undefined) data.orgName           = orgName
      if (billingEmail      !== undefined) data.billingEmail      = billingEmail
      if (minimumConfidence !== undefined) data.minimumConfidence = minimumConfidence
      if (networkOptIn      !== undefined) data.networkOptIn      = networkOptIn

      if (Object.keys(data).length === 0) {
        return reply.code(400).send({ error: { code: 'no_fields', message: 'No fields to update.' } })
      }

      const customer = await prisma.customer.update({
        where: { id: request.params.id },
        data,
      })

      return reply.send({
        id:                customer.id,
        email:             customer.email,
        orgName:           customer.orgName,
        billingEmail:      customer.billingEmail,
        minimumConfidence: customer.minimumConfidence,
        networkOptIn:      customer.networkOptIn,
        updatedAt:         customer.updatedAt,
      })
    }
  )
}
