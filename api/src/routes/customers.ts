import type { FastifyInstance } from 'fastify'
import { prisma } from '../lib/prisma.js'
import crypto from 'node:crypto'

function verifyAdminKey(authHeader: string | undefined): boolean {
  const adminKey = process.env.ADMIN_KEY
  if (!adminKey) return false
  if (!authHeader?.startsWith('Bearer ')) return false
  const provided = authHeader.slice(7)
  // Constant-time comparison
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(adminKey))
  } catch {
    return false
  }
}

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

      let customer = await prisma.customer.findUnique({ where: { email } })

      if (!customer) {
        customer = await prisma.customer.create({
          data: {
            email,
            sandboxWriteKey: `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`,
            sandboxReadKey:  `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
            webhookSecret:   `whsec_${crypto.randomBytes(20).toString('hex')}`,
          },
        })
      }

      return reply.send({
        id:              customer.id,
        email:           customer.email,
        sandboxWriteKey: customer.sandboxWriteKey,
        sandboxReadKey:  customer.sandboxReadKey,
        webhookSecret:   customer.webhookSecret,
        createdAt:       customer.createdAt,
      })
    }
  )

  // POST /v1/customers/:id/live-keys
  // Generate a live write+read key pair. Raw keys returned ONCE — only hashes stored.
  // Deprecates any existing active live keys before creating new ones (14-day overlap applies).
  fastify.post<{ Params: { id: string } }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const customerId = request.params.id

      // Deprecate existing active live keys
      await prisma.apiKey.updateMany({
        where: { customerId, deprecated: false },
        data:  { deprecated: true, deprecatedAt: new Date() },
      })

      const rawWriteKey = `vsk_live_${crypto.randomBytes(20).toString('hex')}`
      const rawReadKey  = `vsk_live_read_${crypto.randomBytes(20).toString('hex')}`
      const hashKey     = (k: string) => crypto.createHash('sha256').update(k).digest('hex')

      const [writeKey, readKey] = await Promise.all([
        prisma.apiKey.create({ data: { customerId, keyHash: hashKey(rawWriteKey), scope: 'write' } }),
        prisma.apiKey.create({ data: { customerId, keyHash: hashKey(rawReadKey),  scope: 'read'  } }),
      ])

      return reply.send({
        writeKey: { id: writeKey.id, rawKey: rawWriteKey, scope: 'write', createdAt: writeKey.createdAt },
        readKey:  { id: readKey.id,  rawKey: rawReadKey,  scope: 'read',  createdAt: readKey.createdAt  },
      })
    }
  )

  // GET /v1/customers/:id/live-keys
  // Returns metadata for active (non-expired) live keys. No raw values.
  fastify.get<{ Params: { id: string } }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const keys = await prisma.apiKey.findMany({
        where:   { customerId: request.params.id, deprecated: false },
        select:  { id: true, scope: true, createdAt: true },
        orderBy: { createdAt: 'desc' },
      })

      return reply.send({ keys })
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
  fastify.patch<{
    Params: { id: string }
    Body: { orgName?: string; billingEmail?: string; minimumConfidence?: string; networkOptIn?: boolean }
  }>(
    '/customers/:id',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const { orgName, billingEmail, minimumConfidence, networkOptIn } = request.body
      const data: Record<string, unknown> = {}
      if (orgName          !== undefined) data.orgName          = orgName
      if (billingEmail     !== undefined) data.billingEmail     = billingEmail
      if (minimumConfidence !== undefined) data.minimumConfidence = minimumConfidence
      if (networkOptIn     !== undefined) data.networkOptIn     = networkOptIn

      if (Object.keys(data).length === 0) {
        return reply.code(400).send({ error: { code: 'no_fields', message: 'No fields to update.' } })
      }

      const customer = await prisma.customer.update({
        where: { id: request.params.id },
        data,
      })

      return reply.send({
        id:              customer.id,
        email:           customer.email,
        orgName:         customer.orgName,
        billingEmail:    customer.billingEmail,
        minimumConfidence: customer.minimumConfidence,
        networkOptIn:    customer.networkOptIn,
        updatedAt:       customer.updatedAt,
      })
    }
  )
}
