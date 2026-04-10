import { FastifyPluginAsync, FastifyRequest } from 'fastify'
import fp from 'fastify-plugin'
import crypto from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { config } from '../config.js'

// §13: API keys are hash-stored. SHA-256(key) is stored, never the raw key.
// §7 Credential scoping:
//   write-scoped: POST endpoints (enroll, verify, complete, fallback)
//   read-scoped:  GET /v1/device/{token}/reputation, GET /v1/verify/{session_id}

export type ApiScope = 'write' | 'read'

declare module 'fastify' {
  interface FastifyRequest {
    customerId: string
    apiKeyId: string
    apiKeyDeprecated: boolean
  }
}

function hashApiKey(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex')
}

function extractBearerToken(request: FastifyRequest): string | null {
  const auth = request.headers.authorization
  if (!auth?.startsWith('Bearer ')) return null
  return auth.slice(7)
}

// §13: 14-day rotation overlap — deprecated keys remain valid until deprecatedAt + 14 days
function isKeyExpired(deprecated: boolean, deprecatedAt: Date | null): boolean {
  if (!deprecated || !deprecatedAt) return false
  const cutoff = new Date(deprecatedAt.getTime() + 14 * 24 * 60 * 60 * 1000)
  return new Date() > cutoff
}

export function makeApiKeyAuthPlugin(requiredScope: ApiScope): FastifyPluginAsync {
  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.addHook('preHandler', async (request, reply) => {
      const rawKey = extractBearerToken(request)
      if (!rawKey) {
        return reply.code(401).send({ error: { code: 'missing_api_key', message: 'Authorization header required.' } })
      }

      const keyHash = hashApiKey(rawKey)
      const apiKey = await prisma.apiKey.findUnique({
        where: { keyHash },
        include: { customer: true },
      })

      if (!apiKey) {
        return reply.code(401).send({ error: { code: 'invalid_api_key', message: 'Invalid API key.' } })
      }

      if (isKeyExpired(apiKey.deprecated, apiKey.deprecatedAt)) {
        return reply.code(401).send({ error: { code: 'api_key_expired', message: 'API key has expired after rotation window.' } })
      }

      if (apiKey.scope !== requiredScope) {
        return reply.code(403).send({ error: { code: 'insufficient_scope', message: `This endpoint requires a ${requiredScope}-scoped API key.` } })
      }

      // Stamp last_used_at (fire and forget — don't block the request)
      prisma.apiKey.update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } }).catch(() => {})

      request.customerId = apiKey.customerId
      request.apiKeyId = apiKey.id
      request.apiKeyDeprecated = apiKey.deprecated

      // §13: SDK detects Vouchflow-Key-Deprecated header
      if (apiKey.deprecated) {
        reply.header('Vouchflow-Key-Deprecated', 'true')
      }
    })
  }

  return fp(plugin, { name: `api-key-auth-${requiredScope}` })
}
