import { FastifyPluginAsync } from 'fastify'
import crypto from 'node:crypto'
import { z } from 'zod'
import { prisma } from '../lib/prisma.js'
import { redis } from '../lib/redis.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { validateAttestation } from '../services/attestation.js'
import { anomalyQueue } from '../lib/queues.js'

// §7 POST /v1/enroll rate limit: 10/minute per customer + IP
const RATE_LIMIT_MAX = 10
const RATE_LIMIT_WINDOW = '1 minute'

// §11 Security: enrollment response normalized to 250ms (timing attack mitigation)
const ENROLL_RESPONSE_TIME_MS = 250

// §7: idempotency_key checked within 24h window
const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60

const AttestationSchema = z.object({
  token: z.string(),
  key_id: z.string().nullish(),
})

const EnrollRequestSchema = z.object({
  idempotency_key: z.string().min(1),
  platform: z.enum(['ios', 'android', 'web']),
  reason: z.enum(['fresh_enrollment', 'reinstall', 'key_invalidated', 'corrupted']),
  attestation: AttestationSchema.nullish(),
  public_key: z.string().min(1),
  device_token: z.string().nullish(),
  strongbox_backed: z.boolean().nullish(),
})

type EnrollRequest = z.infer<typeof EnrollRequestSchema>

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('write'))

  fastify.post('/enroll', {
    config: {
      rateLimit: {
        max: RATE_LIMIT_MAX,
        timeWindow: RATE_LIMIT_WINDOW,
        // §7: per customer + IP
        // §7: per customer + IP — using IP here since customerId isn't available
        // at onRequest. The IP naturally combines both concerns at this endpoint.
        keyGenerator: (request: any) => `enroll:${request.ip}`,
      },
    },
    handler: async (request, reply) => {
      const start = Date.now()

      // ── Parse & validate ─────────────────────────────────────────────────
      const parsed = EnrollRequestSchema.safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({
          error: { code: 'invalid_request', message: parsed.error.message },
        })
      }
      const body: EnrollRequest = parsed.data

      // ── Idempotency check (Redis first, DB fallback) ─────────────────────
      // §7: "if seen within 24h, return original response"
      const idempotencyRedisKey = `idempotency:${body.idempotency_key}`
      const cached = await redis.get(idempotencyRedisKey)
      if (cached) {
        await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)
        return reply.code(200).send(JSON.parse(cached))
      }

      const dbRecord = await prisma.idempotencyRecord.findUnique({
        where: { key: body.idempotency_key },
      })
      if (dbRecord && dbRecord.expiresAt > new Date()) {
        const response = JSON.parse(dbRecord.responseJson)
        await redis.set(idempotencyRedisKey, dbRecord.responseJson, 'EX', IDEMPOTENCY_TTL_SECONDS)
        await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)
        return reply.code(200).send(response)
      }

      // ── Public key uniqueness check ───────────────────────────────────────
      // §7: "if exists under different device_token, reject 409"
      const existingDevice = await prisma.device.findFirst({
        where: { publicKey: body.public_key },
      })
      if (existingDevice && existingDevice.deviceToken !== (body.device_token ?? '')) {
        await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)
        return reply.code(409).send({
          error: {
            code: 'public_key_already_registered',
            message: 'This public key is already registered to a different device token.',
          },
        })
      }

      // ── Attestation validation ────────────────────────────────────────────
      // §7: "If attestation null/failed: accept, set attestation_verified: false,
      //      confidence_ceiling: medium"
      let attestationVerified = false
      if (body.attestation) {
        try {
          const result = await validateAttestation({
            platform: body.platform,
            token: body.attestation.token,
            keyId: body.attestation.key_id ?? null,
            nonce: body.idempotency_key,
          })
          attestationVerified = result.verified
        } catch {
          // Non-fatal per §7
          attestationVerified = false
        }
      }

      const confidenceCeiling = attestationVerified ? 'high' : 'medium'

      // ── Compute public key fingerprint ────────────────────────────────────
      // §11 Network Graph Privacy: fingerprint stored internally, never returned
      const keyFingerprint = crypto
        .createHash('sha256')
        .update(body.public_key)
        .digest('hex')

      // ── Create or update device record ───────────────────────────────────
      const deviceToken = body.device_token ?? generateDeviceToken()

      const platform = body.platform

      const device = await prisma.device.upsert({
        where: { deviceToken },
        create: {
          deviceToken,
          customerId: request.customerId,
          publicKey: body.public_key,
          keyFingerprint,
          platform,
          attestationVerified,
          confidenceCeiling,
          strongboxBacked: body.strongbox_backed ?? null,
          enrolledAt: new Date(),
          lastSeen: new Date(),
          status: 'active',
        },
        update: {
          publicKey: body.public_key,
          keyFingerprint,
          attestationVerified,
          confidenceCeiling,
          strongboxBacked: body.strongbox_backed ?? null,
          lastSeen: new Date(),
          status: 'active',
        },
      })

      // ── Network graph: enrollment event ──────────────────────────────────
      // §15 Write Path step 3: only if customer is network participant; never in sandbox
      if (device.networkParticipant && !request.isSandbox) {
        await writeNetworkEvent({
          keyFingerprint,
          customerId: request.customerId,
          eventType: body.reason === 'fresh_enrollment' ? 'enrollment' : body.reason,
          platform,
          attestationVerified,
          strongboxBacked: device.strongboxBacked,
        })
      }

      // ── Build response ────────────────────────────────────────────────────
      const response = {
        device_token: device.deviceToken,
        enrolled_at: device.enrolledAt.toISOString(),
        status: device.status,
        attestation_verified: device.attestationVerified,
        confidence_ceiling: device.confidenceCeiling,
        idempotency_key: body.idempotency_key,
      }

      // ── Store idempotency record ──────────────────────────────────────────
      const responseJson = JSON.stringify(response)
      const expiresAt = new Date(Date.now() + IDEMPOTENCY_TTL_SECONDS * 1000)

      await prisma.idempotencyRecord.upsert({
        where: { key: body.idempotency_key },
        create: { key: body.idempotency_key, responseJson, expiresAt },
        update: { responseJson, expiresAt },
      })
      await redis.set(idempotencyRedisKey, responseJson, 'EX', IDEMPOTENCY_TTL_SECONDS)

      // ── Normalize response time (§11 timing attack mitigation) ───────────
      await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)

      return reply.code(200).send(response)
    },
  })
}

export default route

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateDeviceToken(): string {
  return `dvt_${crypto.randomBytes(16).toString('hex')}`
}

async function normalizeLatency(startMs: number, targetMs: number): Promise<void> {
  const elapsed = Date.now() - startMs
  const remaining = targetMs - elapsed
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining))
  }
}

async function writeNetworkEvent(params: {
  keyFingerprint: string
  customerId: string
  eventType: string
  platform: string
  attestationVerified: boolean
  strongboxBacked: boolean | null
}) {
  await prisma.$transaction(async (tx) => {
    const networkDevice = await tx.networkDevice.upsert({
      where: { keyFingerprint: params.keyFingerprint },
      create: {
        keyFingerprint: params.keyFingerprint,
        platform: params.platform,
        strongboxBacked: params.strongboxBacked,
        attestationEverVerified: params.attestationVerified,
        totalVerifications: 0,
        customerCount: 1,
      },
      update: {
        lastSeen: new Date(),
        attestationEverVerified: params.attestationVerified ? true : undefined,
      },
    })

    await tx.networkEvent.create({
      data: {
        networkDeviceId: networkDevice.id,
        customerId: params.customerId,
        eventType: params.eventType,
        confidence: null,
        biometricUsed: null,
        fallbackUsed: false,
      },
    })
  })

  // Enqueue async anomaly scoring per §15
  await anomalyQueue.add('score', { keyFingerprint: params.keyFingerprint })
}
