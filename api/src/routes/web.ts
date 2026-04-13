import type { FastifyInstance } from 'fastify'
import { requireSession } from '../middleware/requireSession.js'
import { prisma } from '../lib/prisma.js'
import { createWebhookEndpoint } from '../services/webhookSecrets.js'
import crypto from 'node:crypto'

export default async function webRoutes(fastify: FastifyInstance) {

  fastify.addHook('preHandler', requireSession)

  // GET /web/session — frontend reads this on load to get current user
  fastify.get('/web/session', async (request) => ({
    email:              request.session.get('email'),
    customerId:         request.session.get('customerId'),
    sandboxWriteKey:    maskKey(request.session.get('sandboxWriteKey') as string),
    sandboxReadKey:     maskKey(request.session.get('sandboxReadKey')  as string),
    webhookSecret:      maskKey(request.session.get('webhookSecret')   as string),
    onboardingComplete: request.session.get('onboardingComplete'),
  }))

  // GET /web/overview — dashboard stat cards
  fastify.get('/web/overview', async (request) => {
    const customerId = request.session.get('customerId') as string
    const [verificationCount, deviceCount] = await Promise.all([
      prisma.verification.count({ where: { customerId } }),
      prisma.device.count({ where: { customerId } }),
    ])
    return { verificationCount, deviceCount }
  })

  // GET /web/verifications
  fastify.get<{
    Querystring: { limit?: string; offset?: string; confidence?: string; platform?: string }
  }>('/web/verifications', async (request) => {
    const customerId = request.session.get('customerId') as string
    const limit  = Math.min(parseInt(request.query.limit  ?? '20'), 100)
    const offset = parseInt(request.query.offset ?? '0')

    const rows = await prisma.verification.findMany({
      where: {
        customerId,
        ...(request.query.confidence ? { confidence: request.query.confidence } : {}),
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    })
    return { rows }
  })

  // GET /web/verifications/:sessionId
  fastify.get<{ Params: { sessionId: string } }>(
    '/web/verifications/:sessionId',
    async (request, reply) => {
      const customerId = request.session.get('customerId') as string
      const row = await prisma.verification.findFirst({
        where: { sessionId: request.params.sessionId, customerId },
      })
      if (!row) return reply.status(404).send({ error: 'not_found' })
      return row
    }
  )

  // GET /web/devices
  fastify.get('/web/devices', async (request) => {
    const customerId = request.session.get('customerId') as string
    const devices = await prisma.device.findMany({
      where: { customerId },
      orderBy: { createdAt: 'desc' },
      take: 50,
    })
    return { devices }
  })

  // GET /web/keys — masked keys from session
  fastify.get('/web/keys', async (request) => ({
    sandboxWriteKey: maskKey(request.session.get('sandboxWriteKey') as string),
    sandboxReadKey:  maskKey(request.session.get('sandboxReadKey')  as string),
    webhookSecret:   maskKey(request.session.get('webhookSecret')   as string),
  }))

  // GET /web/usage
  fastify.get('/web/usage', async (request) => {
    const customerId = request.session.get('customerId') as string
    const count = await prisma.verification.count({ where: { customerId } })
    return {
      verificationCount: count,
      periodStart: startOfMonth(),
      periodEnd:   endOfMonth(),
    }
  })

  // PATCH /web/account
  fastify.patch<{
    Body: { orgName?: string; billingEmail?: string; minimumConfidence?: string; networkOptIn?: boolean }
  }>('/web/account', async (request) => {
    const customerId = request.session.get('customerId') as string
    const { orgName, billingEmail, minimumConfidence, networkOptIn } = request.body
    const data: Record<string, unknown> = {}
    if (orgName           !== undefined) data.orgName           = orgName
    if (billingEmail      !== undefined) data.billingEmail      = billingEmail
    if (minimumConfidence !== undefined) data.minimumConfidence = minimumConfidence
    if (networkOptIn      !== undefined) data.networkOptIn      = networkOptIn
    await prisma.customer.update({ where: { id: customerId }, data })
    return { ok: true }
  })

  // POST /web/webhooks
  fastify.post<{ Body: { url: string; events: string[] } }>(
    '/web/webhooks',
    async (request) => {
      const customerId = request.session.get('customerId') as string
      const { url, events } = request.body
      const rawSecret = `whsec_${crypto.randomBytes(20).toString('hex')}`
      const endpoint = await createWebhookEndpoint(customerId, url, rawSecret)
      // Update events on the created record (createWebhookEndpoint doesn't accept events)
      await prisma.webhookEndpoint.update({
        where: { id: endpoint.id },
        data: { events },
      })
      // Return raw secret once — it cannot be recovered after this response
      return { id: endpoint.id, url: endpoint.url, events, createdAt: endpoint.createdAt, secret: rawSecret }
    }
  )

  // DELETE /web/webhooks/:webhookId
  fastify.delete<{ Params: { webhookId: string } }>(
    '/web/webhooks/:webhookId',
    async (request, reply) => {
      const customerId = request.session.get('customerId') as string
      // Verify ownership before deleting
      const endpoint = await prisma.webhookEndpoint.findFirst({
        where: { id: request.params.webhookId, customerId },
      })
      if (!endpoint) return reply.status(404).send({ error: 'not_found' })
      await prisma.webhookEndpoint.delete({ where: { id: endpoint.id } })
      return { ok: true }
    }
  )
}

function maskKey(key: string): string {
  if (!key) return ''
  return key.slice(0, 12) + '••••••••••••••••••••••••••••••••'
}

function startOfMonth(): string {
  const d = new Date(); d.setDate(1); d.setHours(0, 0, 0, 0)
  return d.toISOString()
}

function endOfMonth(): string {
  const d = new Date(); d.setMonth(d.getMonth() + 1); d.setDate(0); d.setHours(23, 59, 59, 999)
  return d.toISOString()
}
