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

  // Hard cap on simultaneously-active live keys per customer. Matches Stripe's
  // limit and gives us headroom to debug "we hit the limit" support tickets
  // before infinite-key sprawl becomes a security review burden.
  const MAX_ACTIVE_KEYS_PER_CUSTOMER = 10

  // POST /v1/customers/:id/live-keys
  // Create one or more live keys. Raw keys returned ONCE — only hashes stored.
  // Existing keys are NOT deprecated; customers may run up to MAX_ACTIVE_KEYS
  // simultaneously (per-platform / per-environment isolation).
  //
  // Body shape:
  //   {} or { scope: 'pair' }   → write+read pair (back-compat default)
  //   { scope: 'write' }        → single write key
  //   { scope: 'read' }         → single read key
  fastify.post<{
    Params: { id: string }
    Body: { scope?: 'pair' | 'write' | 'read' }
  }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const customerId = request.params.id
      const scope = request.body?.scope ?? 'pair'
      if (scope !== 'pair' && scope !== 'write' && scope !== 'read') {
        return reply.code(400).send({
          error: { code: 'invalid_request', message: 'scope must be "pair", "write", or "read".' },
        })
      }

      const keysToCreate = scope === 'pair' ? 2 : 1
      const activeCount = await prisma.apiKey.count({
        where: { customerId, deprecated: false },
      })
      if (activeCount + keysToCreate > MAX_ACTIVE_KEYS_PER_CUSTOMER) {
        return reply.code(409).send({
          error: {
            code: 'key_limit_reached',
            message: `Maximum ${MAX_ACTIVE_KEYS_PER_CUSTOMER} active live keys per customer. Revoke an existing key first.`,
          },
        })
      }

      const hashKey = (k: string) => crypto.createHash('sha256').update(k).digest('hex')
      const generate = (s: 'write' | 'read'): { rawKey: string; hash: string } => {
        const raw = s === 'write'
          ? `vsk_live_${crypto.randomBytes(20).toString('hex')}`
          : `vsk_live_read_${crypto.randomBytes(20).toString('hex')}`
        return { rawKey: raw, hash: hashKey(raw) }
      }

      if (scope === 'pair') {
        const w = generate('write')
        const r = generate('read')
        const [writeKey, readKey] = await Promise.all([
          prisma.apiKey.create({ data: { customerId, keyHash: w.hash, scope: 'write' } }),
          prisma.apiKey.create({ data: { customerId, keyHash: r.hash, scope: 'read'  } }),
        ])
        return reply.send({
          writeKey: { id: writeKey.id, rawKey: w.rawKey, scope: 'write', createdAt: writeKey.createdAt },
          readKey:  { id: readKey.id,  rawKey: r.rawKey, scope: 'read',  createdAt: readKey.createdAt  },
        })
      }

      // single-scope creation
      const g = generate(scope)
      const created = await prisma.apiKey.create({
        data: { customerId, keyHash: g.hash, scope },
      })
      return reply.send({
        key: { id: created.id, rawKey: g.rawKey, scope, createdAt: created.createdAt },
      })
    }
  )

  // GET /v1/customers/:id/live-keys
  // Returns metadata for active (non-deprecated) live keys. No raw values.
  fastify.get<{ Params: { id: string } }>(
    '/customers/:id/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const keys = await prisma.apiKey.findMany({
        where:   { customerId: request.params.id, deprecated: false },
        select:  { id: true, scope: true, createdAt: true, lastUsedAt: true },
        orderBy: { createdAt: 'desc' },
      })

      return reply.send({ keys })
    }
  )

  // DELETE /v1/customers/:id/live-keys/:keyId
  // Revokes a single live key by marking it deprecated. The 14-day grace
  // window declared in the schema (deprecatedAt + 14d) still applies — we
  // don't immediately invalidate so callers mid-flight aren't 401'd.
  fastify.delete<{ Params: { id: string; keyId: string } }>(
    '/customers/:id/live-keys/:keyId',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const { id: customerId, keyId } = request.params
      const key = await prisma.apiKey.findFirst({
        where: { id: keyId, customerId },
      })
      if (!key) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Key not found.' } })
      }
      if (key.deprecated) {
        return reply.code(409).send({ error: { code: 'already_revoked', message: 'Key is already deprecated.' } })
      }

      const updated = await prisma.apiKey.update({
        where: { id: keyId },
        data:  { deprecated: true, deprecatedAt: new Date() },
        select: { id: true, scope: true, deprecatedAt: true },
      })
      return reply.send({ key: updated })
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
    Body: {
      orgName?: string
      billingEmail?: string
      minimumConfidence?: string
      networkOptIn?: boolean
      // Per-customer attestation parameters. Strings to clear (null) or set.
      androidPackageName?: string | null
      androidSigningKeySha256?: string | null
      iosTeamId?: string | null
      iosBundleId?: string | null
    }
  }>(
    '/customers/:id',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }

      const {
        orgName, billingEmail, minimumConfidence, networkOptIn,
        androidPackageName, androidSigningKeySha256, iosTeamId, iosBundleId,
      } = request.body

      // Light-touch validation — these values feed attestation comparisons,
      // so a typo here silently caps customer confidence at medium without
      // any obvious error. Reject obviously-malformed values up front.
      if (androidPackageName !== undefined && androidPackageName !== null) {
        if (!/^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+$/.test(androidPackageName)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'androidPackageName must be a reverse-DNS Java package name.' } })
        }
      }
      if (androidSigningKeySha256 !== undefined && androidSigningKeySha256 !== null) {
        const normalized = androidSigningKeySha256.replace(/[:\s]/g, '').toLowerCase()
        if (!/^[0-9a-f]{64}$/.test(normalized)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'androidSigningKeySha256 must be 64 hex characters (colons and whitespace are stripped).' } })
        }
      }
      if (iosTeamId !== undefined && iosTeamId !== null) {
        if (!/^[A-Z0-9]{10}$/.test(iosTeamId)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'iosTeamId must be 10 uppercase alphanumeric characters.' } })
        }
      }
      if (iosBundleId !== undefined && iosBundleId !== null) {
        if (!/^[a-zA-Z][\w-]*(\.[a-zA-Z][\w-]*)+$/.test(iosBundleId)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'iosBundleId must be a reverse-DNS bundle identifier.' } })
        }
      }

      const data: Record<string, unknown> = {}
      if (orgName                 !== undefined) data.orgName                 = orgName
      if (billingEmail            !== undefined) data.billingEmail            = billingEmail
      if (minimumConfidence       !== undefined) data.minimumConfidence       = minimumConfidence
      if (networkOptIn            !== undefined) data.networkOptIn            = networkOptIn
      if (androidPackageName      !== undefined) data.androidPackageName      = androidPackageName
      if (androidSigningKeySha256 !== undefined) {
        data.androidSigningKeySha256 = androidSigningKeySha256 === null
          ? null
          : androidSigningKeySha256.replace(/[:\s]/g, '').toLowerCase()
      }
      if (iosTeamId               !== undefined) data.iosTeamId               = iosTeamId
      if (iosBundleId             !== undefined) data.iosBundleId             = iosBundleId

      if (Object.keys(data).length === 0) {
        return reply.code(400).send({ error: { code: 'no_fields', message: 'No fields to update.' } })
      }

      const customer = await prisma.customer.update({
        where: { id: request.params.id },
        data,
      })

      return reply.send({
        id:                      customer.id,
        email:                   customer.email,
        orgName:                 customer.orgName,
        billingEmail:            customer.billingEmail,
        minimumConfidence:       customer.minimumConfidence,
        networkOptIn:            customer.networkOptIn,
        androidPackageName:      customer.androidPackageName,
        androidSigningKeySha256: customer.androidSigningKeySha256,
        iosTeamId:               customer.iosTeamId,
        iosBundleId:             customer.iosBundleId,
        updatedAt:               customer.updatedAt,
      })
    }
  )
}
