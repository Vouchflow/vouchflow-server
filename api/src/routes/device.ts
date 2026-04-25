import { FastifyPluginAsync } from 'fastify'
import { prisma } from '../lib/prisma.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'

// §7 GET /v1/device/{device_token}/reputation
// Requires read-scoped API key (server-side only, never in mobile SDK)
// §7 rate limit: 1000/minute per customer

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('read'))

  fastify.get<{ Params: { device_token: string } }>('/device/:device_token/reputation', {
    config: {
      rateLimit: {
        max: 1000,
        timeWindow: '1 minute',
        keyGenerator: (req: any) => `reputation:${req.ip}`,
      },
    },
    handler: async (request, reply) => {
      const { device_token } = request.params

      const device = await prisma.device.findUnique({ where: { deviceToken: device_token } })

      if (!device) {
        return reply.code(404).send({ error: { code: 'device_not_found', message: 'Device token not found.' } })
      }

      // §7: read-scoped key must belong to the customer who owns the device
      if (device.customerId !== request.customerId) {
        return reply.code(403).send({ error: { code: 'forbidden', message: 'Device does not belong to this customer.' } })
      }

      // Fetch most recent completed verification and network graph data in parallel
      const [recentVerification, networkDevice] = await Promise.all([
        prisma.verification.findFirst({
          where: { deviceId: device.id, state: 'COMPLETED' },
          orderBy: { completedAt: 'desc' },
          select: { confidence: true, context: true, completedAt: true, biometricUsed: true, fallbackUsed: true },
        }),
        device.keyFingerprint
          ? prisma.networkDevice.findUnique({ where: { keyFingerprint: device.keyFingerprint } })
          : null,
      ])

      const now = Date.now()
      const deviceAgeDays = Math.floor((now - device.enrolledAt.getTime()) / (1000 * 60 * 60 * 24))

      return reply.code(200).send({
        device_token: device.deviceToken,
        first_seen: device.enrolledAt.toISOString(),
        last_seen: device.lastSeen?.toISOString() ?? device.enrolledAt.toISOString(),
        total_verifications: networkDevice?.totalVerifications ?? 0,
        network_verifications: networkDevice?.totalVerifications ?? 0,
        anomaly_flags: networkDevice?.anomalyFlags ?? [],
        risk_score: networkDevice?.riskScore ?? 0,
        device_age_days: deviceAgeDays,
        platform: device.platform,
        keychain_persistent: true,  // §9: iOS Keychain AfterFirstUnlock; Android AccountManager
        network_participant: device.networkParticipant,
        last_verification: recentVerification
          ? {
              confidence: recentVerification.confidence,
              context: recentVerification.context,
              completed_at: recentVerification.completedAt!.toISOString(),
              biometric_used: recentVerification.biometricUsed ?? false,
              fallback_used: recentVerification.fallbackUsed,
            }
          : null,
      })
    },
  })
}

export default route
