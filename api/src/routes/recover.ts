import { FastifyPluginAsync } from 'fastify'
import crypto from 'node:crypto'
import { z } from 'zod'
import { prisma } from '../lib/prisma.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { extractRpIdFromClientData, verifyWebAuthnAssertion } from '../services/webauthn.js'

const SESSION_EXPIRY_SECONDS = 60

const CompleteSchema = z.object({
  session_id: z.string().min(1),
  credential_id: z.string().regex(/^[A-Za-z0-9_-]+$/),
  client_data_json: z.string().min(1),
  authenticator_data: z.string().min(1),
  signed_challenge: z.string().min(1),
  user_handle: z.string().optional(),
})

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('write'))

  fastify.post('/device/recover/initiate', {
    config: {
      rateLimit: {
        max: 100,
        timeWindow: '1 minute',
        keyGenerator: (request: any) => `recover_initiate:${request.ip}`,
      },
    },
    handler: async (request, reply) => {
      const parsed = z.object({}).safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({
          error: { code: 'invalid_request', message: parsed.error.message },
        })
      }

      const challenge = crypto.randomBytes(32).toString('base64')
      const sessionId = `ses_${crypto.randomBytes(12).toString('hex')}`
      const expiresAt = new Date(Date.now() + SESSION_EXPIRY_SECONDS * 1000)

      await prisma.verification.create({
        data: {
          sessionId,
          customerId: request.customerId,
          appId: request.appId,
          challenge,
          state: 'INITIATED',
          type: 'recover',
          expiresAt,
          isSandbox: request.isSandbox,
        },
      })

      return reply.code(200).send({
        session_id: sessionId,
        challenge,
        expires_at: expiresAt.toISOString(),
      })
    },
  })

  fastify.post('/device/recover/complete', {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: '1 minute',
        keyGenerator: (request: any) => `recover_complete:${request.ip}`,
      },
    },
    handler: async (request, reply) => {
      const parsed = CompleteSchema.safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({
          error: { code: 'invalid_request', message: parsed.error.message },
        })
      }
      const body = parsed.data

      const session = await prisma.verification.findFirst({
        where: {
          sessionId: body.session_id,
          customerId: request.customerId,
          appId: request.appId,
        },
      })
      if (!session) {
        return reply.code(404).send({
          error: { code: 'session_not_found', message: 'Session not found.' },
        })
      }
      if (session.type !== 'recover') {
        return reply.code(409).send({
          error: { code: 'invalid_session_type', message: 'Session is not a recovery session.' },
        })
      }
      if (session.state !== 'INITIATED' || session.challengeConsumed) {
        return reply.code(session.state === 'EXPIRED' ? 410 : 409).send({
          error: {
            code: session.state === 'EXPIRED' ? 'session_expired' : 'invalid_session_state',
            message: `Session is in state ${session.state}.`,
          },
        })
      }
      if (new Date() > session.expiresAt) {
        await prisma.verification.updateMany({
          where: { id: session.id, state: 'INITIATED' },
          data: { state: 'EXPIRED' },
        })
        return reply.code(410).send({
          error: { code: 'session_expired', message: 'Recovery session expired after 60 seconds.' },
        })
      }

      const device = await prisma.device.findFirst({
        where: {
          credentialId: body.credential_id,
          customerId: request.customerId,
          appId: request.appId,
          platform: 'web',
          status: 'active',
        },
      })
      if (!device) {
        await prisma.verification.updateMany({
          where: { id: session.id, state: 'INITIATED' },
          data: { state: 'FAILED', completedAt: new Date() },
        })
        return reply.code(404).send({
          error: { code: 'device_not_found', message: 'Device not found.' },
        })
      }

      let expectedRpId: string
      try {
        expectedRpId = extractRpIdFromClientData(body.client_data_json)
      } catch {
        expectedRpId = ''
      }
      let assertionResult: { valid: boolean; reason?: string }
      try {
        assertionResult = verifyWebAuthnAssertion({
          publicKey: device.publicKey,
          challenge: session.challenge,
          clientDataJSON: body.client_data_json,
          authenticatorData: body.authenticator_data,
          signature: body.signed_challenge,
          expectedRpId,
        })
      } catch {
        // A syntactically valid base64 string can still decode to malformed
        // client data (for example JSON null). Treat it as a bad assertion.
        assertionResult = { valid: false, reason: 'malformed_assertion' }
      }
      if (!assertionResult.valid) {
        request.log.warn(
          { sessionId: session.sessionId, reason: assertionResult.reason },
          'Recovery assertion verification failed',
        )
        await prisma.verification.updateMany({
          where: { id: session.id, state: 'INITIATED' },
          data: { state: 'FAILED', completedAt: new Date() },
        })
        return reply.code(422).send({
          error: { code: 'invalid_signature', message: 'WebAuthn assertion verification failed.' },
        })
      }

      const completedAt = new Date()
      const completed = await prisma.$transaction(async (tx) => {
        const updated = await tx.verification.updateMany({
          where: {
            id: session.id,
            state: 'INITIATED',
            challengeConsumed: false,
            expiresAt: { gt: completedAt },
          },
          data: {
            deviceId: device.id,
            challengeConsumed: true,
            state: 'COMPLETED',
            completedAt,
            biometricUsed: true,
          },
        })
        if (updated.count === 0) return false
        await tx.device.update({
          where: { id: device.id },
          data: { lastSeen: completedAt },
        })
        return true
      })
      if (!completed) {
        return reply.code(new Date() > session.expiresAt ? 410 : 409).send({
          error: {
            code: new Date() > session.expiresAt ? 'session_expired' : 'invalid_session_state',
            message: 'Recovery session is no longer available.',
          },
        })
      }

      return reply.code(200).send({
        device_token: device.deviceToken,
        credential_id: device.credentialId,
      })
    },
  })
}

export default route
