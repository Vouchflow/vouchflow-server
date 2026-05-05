// Webhook endpoint CRUD. Per-customer scoped via the existing apiKeyAuth
// plugin — we don't surface the legacy ADMIN_KEY here.
//
// All routes require write scope: a webhook endpoint is configuration for
// the customer's app, not a read of verification data, so listing one's
// own endpoints is treated as a write-equivalent permission.
//
// Secret handling: each endpoint gets its own raw whsec_*** secret minted
// at create time. Returned ONCE in the POST response, then encrypted at
// rest via pgp_sym_encrypt and never returned again. Subsequent reads
// only ever return metadata.

import type { FastifyPluginAsync } from 'fastify'
import { z } from 'zod'
import crypto from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { encryptWebhookSecret } from '../services/webhookSecrets.js'

// Set of events the server is wired to actually emit. Keep in sync with the
// WebhookPayload union in services/webhooks.ts.
export const KNOWN_WEBHOOK_EVENTS = [
  'verification.complete',
  'verification.fallback_complete',
] as const

const MAX_ENDPOINTS_PER_CUSTOMER = 5

const CreateBody = z.object({
  url:    z.string().url('url must be a valid URL'),
  events: z.array(z.enum(KNOWN_WEBHOOK_EVENTS)).min(1, 'events must contain at least one event'),
})

const PatchBody = z.object({
  url:    z.string().url().optional(),
  events: z.array(z.enum(KNOWN_WEBHOOK_EVENTS)).min(1).optional(),
}).refine(
  (body) => body.url !== undefined || body.events !== undefined,
  { message: 'must include url or events' },
)

// Allow http://localhost in non-prod for local development; require https
// everywhere else. Catches the most common foot-gun (forgetting the s) and
// blocks accidental data exfil to user-supplied unencrypted endpoints.
function validateUrl(url: string): string | null {
  let parsed: URL
  try { parsed = new URL(url) } catch { return 'url is not parseable' }

  const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
  if (isLocalhost && process.env.NODE_ENV === 'production') {
    return 'localhost URLs are not allowed in production'
  }
  if (parsed.protocol !== 'https:' && !isLocalhost) {
    return 'url must use https'
  }
  return null
}

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('write'))

  // POST /v1/webhooks — create endpoint, return raw secret ONCE
  fastify.post<{ Body: { url?: string; events?: string[] } }>(
    '/webhooks',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const parsed = CreateBody.safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.issues[0]?.message ?? 'invalid body' } })
      }
      const urlError = validateUrl(parsed.data.url)
      if (urlError) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: urlError } })
      }

      const customerId = request.customerId
      const existing = await prisma.webhookEndpoint.count({ where: { customerId } })
      if (existing >= MAX_ENDPOINTS_PER_CUSTOMER) {
        return reply.code(409).send({
          error: {
            code: 'endpoint_limit_reached',
            message: `Maximum ${MAX_ENDPOINTS_PER_CUSTOMER} webhook endpoints per customer.`,
          },
        })
      }

      const rawSecret = `whsec_${crypto.randomBytes(24).toString('hex')}`
      const secretEncrypted = await encryptWebhookSecret(rawSecret)

      const endpoint = await prisma.webhookEndpoint.create({
        data: {
          customerId,
          url:    parsed.data.url,
          events: parsed.data.events,
          secretEncrypted,
        },
      })

      return reply.code(201).send({
        id:        endpoint.id,
        url:       endpoint.url,
        events:    endpoint.events,
        secret:    rawSecret,
        createdAt: endpoint.createdAt.toISOString(),
      })
    },
  )

  // GET /v1/customers/:id/webhooks — list metadata (no secrets)
  // The :id param is decorative; scope comes from request.customerId.
  fastify.get(
    '/customers/:id/webhooks',
    {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
    },
    async (request) => {
      const endpoints = await prisma.webhookEndpoint.findMany({
        where: { customerId: request.customerId },
        orderBy: { createdAt: 'asc' },
      })
      return {
        webhooks: endpoints.map(e => ({
          id:        e.id,
          url:       e.url,
          events:    e.events,
          createdAt: e.createdAt.toISOString(),
        })),
      }
    },
  )

  // PATCH /v1/webhooks/:id — update url and/or events
  fastify.patch<{ Params: { id: string }; Body: { url?: string; events?: string[] } }>(
    '/webhooks/:id',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const parsed = PatchBody.safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.issues[0]?.message ?? 'invalid body' } })
      }
      if (parsed.data.url !== undefined) {
        const urlError = validateUrl(parsed.data.url)
        if (urlError) {
          return reply.code(400).send({ error: { code: 'invalid_request', message: urlError } })
        }
      }

      // Scope to the auth'd customer. updateMany returns count=0 if the
      // endpoint belongs to a different customer or doesn't exist — same
      // 404 either way to avoid leaking existence.
      const result = await prisma.webhookEndpoint.updateMany({
        where: { id: request.params.id, customerId: request.customerId },
        data: parsed.data,
      })
      if (result.count === 0) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Webhook endpoint not found.' } })
      }

      const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: request.params.id } })
      return reply.send({
        id:        endpoint!.id,
        url:       endpoint!.url,
        events:    endpoint!.events,
        createdAt: endpoint!.createdAt.toISOString(),
      })
    },
  )

  // DELETE /v1/webhooks/:id — also deletes child WebhookDelivery rows
  fastify.delete<{ Params: { id: string } }>(
    '/webhooks/:id',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const found = await prisma.webhookEndpoint.findFirst({
        where: { id: request.params.id, customerId: request.customerId },
      })
      if (!found) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Webhook endpoint not found.' } })
      }
      await prisma.$transaction([
        prisma.webhookDelivery.deleteMany({ where: { endpointId: found.id } }),
        prisma.webhookEndpoint.delete({ where: { id: found.id } }),
      ])
      return reply.code(204).send()
    },
  )
}

export default route
