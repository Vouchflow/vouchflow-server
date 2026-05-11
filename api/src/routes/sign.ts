import { FastifyPluginAsync } from 'fastify'
import crypto from 'node:crypto'
import { z } from 'zod'
import { prisma } from '../lib/prisma.js'
import { redis } from '../lib/redis.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { computeConfidence } from '../services/confidence.js'
import { dispatchWebhook } from '../services/webhooks.js'
import {
  verifyWebAuthnAssertion,
  extractRpIdFromClientData,
} from '../services/webauthn.js'
import { signAssertion } from '../services/signingKeys.js'
import { config } from '../config.js'

// Sessions for /v1/sign expire after 60 seconds — same as verify.
const SESSION_EXPIRY_SECONDS = 60

const SIGN_INITIATE_RATE = { max: 100, window: '1 minute' }
const SIGN_COMPLETE_RATE = { max: 10, window: '1 minute' }

const SIGN_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60

const InitiateSchema = z.object({
  device_token: z.string().min(1),
  context: z.string().min(1),
  // Canonicalized JSON string (RFC 8785 JCS) produced client-side.
  // The server stores its SHA-256 in payload_sha256 and includes that hash
  // (never the payload itself) in the signed JWS assertion.
  canonicalized_payload: z.string().min(1),
  minimum_confidence: z.enum(['high', 'medium', 'low']).optional(),
  /** Optional replay-safe key — if the same key is seen within 24h the
   *  original {session_id, challenge} response is returned, so retries
   *  after a dropped response don't mint extra sessions. */
  idempotency_key: z.string().min(1).optional(),
})

const CompleteSchema = z.object({
  device_token: z.string().min(1),
  signed_challenge: z.string().min(1),
  client_data_json: z.string().min(1),
  authenticator_data: z.string().min(1),
  credential_id: z.string().min(1),
})

const CONFIDENCE_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 }
function meets(ceiling: string, minimum: string): boolean {
  return (CONFIDENCE_RANK[ceiling] ?? 0) >= (CONFIDENCE_RANK[minimum] ?? 0)
}

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('write'))

  // ── POST /v1/sign — initiate sign session ────────────────────────────────
  fastify.post('/sign', {
    config: {
      rateLimit: {
        max: SIGN_INITIATE_RATE.max,
        timeWindow: SIGN_INITIATE_RATE.window,
        keyGenerator: (req: any) => `sign:${req.ip}`,
      },
    },
    handler: async (request, reply) => {
      const parsed = InitiateSchema.safeParse(request.body)
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const body = parsed.data

      // ── Idempotency replay (Redis-first, DB fallback) ────────────────────
      if (body.idempotency_key) {
        const cacheKey = `sign_idem:${request.customerId}:${body.idempotency_key}`
        const cached = await redis.get(cacheKey).catch(() => null)
        if (cached) return reply.code(200).send(JSON.parse(cached))
      }

      const device = await prisma.device.findUnique({ where: { deviceToken: body.device_token } })
      if (!device) {
        return reply
          .code(404)
          .send({ error: { code: 'device_not_found', message: 'Device token not found.' } })
      }
      if (device.customerId !== request.customerId) {
        return reply
          .code(403)
          .send({ error: { code: 'device_not_owned', message: 'Device does not belong to this customer.' } })
      }
      if (device.status !== 'active') {
        return reply
          .code(409)
          .send({ error: { code: 'device_inactive', message: `Device status is ${device.status}.` } })
      }
      // Sign requires a web device (WebAuthn assertion path).
      if (device.platform !== 'web') {
        return reply.code(422).send({
          error: { code: 'unsupported_platform', message: 'POST /v1/sign requires platform=web.' },
        })
      }

      const minConfidence = body.minimum_confidence ?? 'high'
      if (!meets(device.confidenceCeiling, minConfidence)) {
        return reply.code(422).send({
          error: {
            code: 'verification_impossible',
            message: `Device cannot meet minimum_confidence: ${minConfidence}. Ceiling is ${device.confidenceCeiling}.`,
          },
        })
      }

      const challenge = crypto.randomBytes(32).toString('base64')
      const sessionId = `ses_${crypto.randomBytes(12).toString('hex')}`
      const expiresAt = new Date(Date.now() + SESSION_EXPIRY_SECONDS * 1000)
      const payloadSha256 = crypto
        .createHash('sha256')
        .update(body.canonicalized_payload, 'utf8')
        .digest('hex')

      await prisma.verification.create({
        data: {
          sessionId,
          deviceId: device.id,
          customerId: request.customerId,
          challenge,
          state: 'INITIATED',
          type: 'sign',
          context: body.context,
          canonicalizedPayload: body.canonicalized_payload,
          payloadSha256,
          expiresAt,
          isSandbox: request.isSandbox,
        },
      })

      const response = {
        session_id: sessionId,
        challenge,
        expires_at: expiresAt.toISOString(),
        session_state: 'INITIATED' as const,
        payload_sha256: payloadSha256,
      }
      if (body.idempotency_key) {
        const cacheKey = `sign_idem:${request.customerId}:${body.idempotency_key}`
        await redis
          .set(cacheKey, JSON.stringify(response), 'EX', SIGN_IDEMPOTENCY_TTL_SECONDS)
          .catch(() => undefined)
      }
      return reply.code(200).send(response)
    },
  })

  // ── POST /v1/sign/:session_id/complete — complete sign session ───────────
  fastify.post<{ Params: { session_id: string } }>('/sign/:session_id/complete', {
    config: {
      rateLimit: {
        max: SIGN_COMPLETE_RATE.max,
        timeWindow: SIGN_COMPLETE_RATE.window,
        keyGenerator: (req: any) => `sign_complete:${req.params.session_id}`,
      },
    },
    handler: async (request, reply) => {
      const { session_id } = request.params

      const parsed = CompleteSchema.safeParse(request.body)
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: { code: 'invalid_request', message: parsed.error.message } })
      }
      const body = parsed.data

      const session = await prisma.verification.findUnique({ where: { sessionId: session_id } })
      if (!session) {
        return reply
          .code(404)
          .send({ error: { code: 'session_not_found', message: 'Session not found.' } })
      }
      if (session.type !== 'sign') {
        return reply.code(409).send({
          error: { code: 'invalid_session_type', message: 'Session is not a sign session.' },
        })
      }
      if (session.state !== 'INITIATED') {
        return reply.code(409).send({
          error: {
            code: 'invalid_session_state',
            message: `Session is in state ${session.state}, expected INITIATED.`,
            current_state: session.state,
          },
        })
      }
      if (new Date() > session.expiresAt) {
        await prisma.verification.update({
          where: { sessionId: session_id },
          data: { state: 'EXPIRED' },
        })
        return reply.code(410).send({
          error: { code: 'session_expired', message: 'Sign session expired after 60 seconds.' },
        })
      }

      const device = await prisma.device.findUnique({ where: { id: session.deviceId! } })
      if (!device || device.deviceToken !== body.device_token) {
        return reply.code(403).send({
          error: { code: 'device_token_mismatch', message: 'device_token does not match the session.' },
        })
      }

      // Atomic single-use check
      const updated = await prisma.verification.updateMany({
        where: { sessionId: session_id, challengeConsumed: false },
        data: { challengeConsumed: true },
      })
      if (updated.count === 0) {
        return reply.code(409).send({
          error: { code: 'challenge_already_consumed', message: 'Challenge has already been used.' },
        })
      }

      // Verify WebAuthn assertion. Same path as POST /v1/verify/:session_id/complete.
      let expectedRpId: string
      try {
        expectedRpId = extractRpIdFromClientData(body.client_data_json)
      } catch {
        return reply.code(400).send({
          error: { code: 'invalid_client_data', message: 'Cannot parse origin from clientDataJSON.' },
        })
      }

      const assertionResult = verifyWebAuthnAssertion({
        publicKey: device.publicKey,
        challenge: session.challenge,
        clientDataJSON: body.client_data_json,
        authenticatorData: body.authenticator_data,
        signature: body.signed_challenge,
        expectedRpId,
      })

      if (!assertionResult.valid) {
        request.log.warn(
          { sessionId: session_id, reason: assertionResult.reason },
          'Sign assertion verification failed',
        )
        await prisma.verification.update({
          where: { sessionId: session_id },
          data: { state: 'FAILED', completedAt: new Date() },
        })
        return reply.code(422).send({
          error: { code: 'invalid_signature', message: 'WebAuthn assertion verification failed.' },
        })
      }

      // Compute confidence (UV flag verified inside webauthn.verifyWebAuthnAssertion)
      const confidence = computeConfidence({
        device,
        biometricUsed: true,
        fallbackUsed: false,
      })

      const completedAt = new Date()
      await prisma.verification.update({
        where: { sessionId: session_id },
        data: {
          state: 'COMPLETED',
          biometricUsed: true,
          confidence,
          completedAt,
        },
      })
      await prisma.device.update({
        where: { id: device.id },
        data: { lastSeen: new Date() },
      })

      // Build the JWS assertion payload (the customer-verifiable bundle).
      // signing_device_id is the stable per-credential identifier we expose
      // to customers — it's the WebAuthn credentialId, not the device_token.
      const signingDeviceId = device.credentialId
        ? `sdv_${crypto
            .createHash('sha256')
            .update(device.credentialId)
            .digest('hex')
            .slice(0, 32)}`
        : `sdv_${crypto
            .createHash('sha256')
            .update(device.deviceToken)
            .digest('hex')
            .slice(0, 32)}`

      const jwsPayload: Record<string, unknown> = {
        v: 1,
        iss: 'https://vouchflow.dev',
        aud: request.customerId,
        context: session.context,
        device_token: device.deviceToken,
        signing_device_id: signingDeviceId,
        confidence,
        payload_sha256: session.payloadSha256,
        session_id,
      }

      const assertion = await signAssertion(jwsPayload)

      // Webhook (mirrors verify.complete dispatch)
      await dispatchWebhook(session.customerId, {
        event: 'sign.complete',
        session_id,
        verified: true,
        confidence,
        context: session.context,
        timestamp: completedAt.toISOString(),
        api_version: config.apiVersion,
      })

      return reply.code(200).send({
        verified: true,
        confidence,
        device_token: device.deviceToken,
        signing_device_id: signingDeviceId,
        signed_at: completedAt.toISOString(),
        assertion,
        session_id,
      })
    },
  })
}

export default route
