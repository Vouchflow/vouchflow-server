import { Worker, UnrecoverableError } from 'bullmq'
import crypto from 'node:crypto'
import { redis } from '../lib/redis.js'
import { prisma } from '../lib/prisma.js'
import { decryptWebhookSecret } from '../services/webhookSecrets.js'

// ─── Anomaly Scoring Worker (§15) ─────────────────────────────────────────────
// Three MVP patterns: velocity, reinstall, confidence degradation
// Full risk score contributions per §15.

const anomalyWorker = new Worker(
  'anomaly',
  async (job) => {
    const { keyFingerprint } = job.data as { keyFingerprint: string }

    const networkDevice = await prisma.networkDevice.findUnique({
      where: { keyFingerprint },
    })
    if (!networkDevice) return

    // Pull recent events for scoring
    const now = new Date()
    const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
    const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

    const recentEvents = await prisma.networkEvent.findMany({
      where: { networkDeviceId: networkDevice.id, occurredAt: { gte: last30Days } },
      orderBy: { occurredAt: 'desc' },
    })

    let riskScore = 0
    const anomalyFlags: string[] = []

    // §15: Device age < 7 days → +20
    const deviceAgeDays = (now.getTime() - networkDevice.firstSeen.getTime()) / (1000 * 60 * 60 * 24)
    if (deviceAgeDays < 7) {
      riskScore += 20
    }

    // §15: Attestation never verified → +15
    if (!networkDevice.attestationEverVerified) {
      riskScore += 15
    }

    // §15: Single app only, age < 30 days → +10
    if (networkDevice.customerCount <= 1 && deviceAgeDays < 30) {
      riskScore += 10
    }

    // §15: Velocity anomaly — >5 new app enrollments in 7 days → +30
    const recentEnrollments = await prisma.networkEvent.count({
      where: {
        networkDeviceId: networkDevice.id,
        eventType: 'enrollment',
        occurredAt: { gte: last7Days },
      },
    })
    if (recentEnrollments > 5) {
      riskScore += 30
      anomalyFlags.push('velocity_anomaly')
    }

    // §15: Reinstall anomaly — >3 reinstalls in 30 days → +25
    const recentReinstalls = await prisma.networkEvent.count({
      where: {
        networkDeviceId: networkDevice.id,
        eventType: 'reinstall',
        occurredAt: { gte: last30Days },
      },
    })
    if (recentReinstalls > 3) {
      riskScore += 25
      anomalyFlags.push('reinstall_anomaly')
    }

    // §15: Confidence degradation — last 3 events low after history of high → +20
    const last3Events = recentEvents.slice(0, 3)
    if (last3Events.length === 3 && last3Events.every((e) => e.confidence === 'low')) {
      const olderHighEvent = recentEvents.find((e) => e.confidence === 'high')
      if (olderHighEvent) {
        riskScore += 20
        anomalyFlags.push('confidence_degradation')
      }
    }

    // Cap at 100
    riskScore = Math.min(riskScore, 100)

    await prisma.networkDevice.update({
      where: { id: networkDevice.id },
      data: { riskScore, anomalyFlags },
    })
  },
  { connection: redis, concurrency: 5 },
)

// ─── Webhook Delivery Worker (§7) ─────────────────────────────────────────────
// Retry schedule: Immediate → 5s → 30s → 2m → 10m → 1h → 6h → 24h → webhook_failed
// 8 attempts total (1 immediate + 7 retries)

const WEBHOOK_DELAYS_MS = [0, 5_000, 30_000, 120_000, 600_000, 3_600_000, 21_600_000, 86_400_000]

const webhookWorker = new Worker(
  'webhooks',
  async (job) => {
    const { deliveryId, url, endpointId } = job.data as {
      deliveryId: string
      url: string
      endpointId: string
    }

    const delivery = await prisma.webhookDelivery.findUnique({ where: { id: deliveryId } })
    if (!delivery || delivery.status === 'delivered') return

    await prisma.webhookDelivery.update({
      where: { id: deliveryId },
      data: { attempts: { increment: 1 }, lastAttemptAt: new Date() },
    })

    // Decrypt the webhook secret for HMAC signing.
    // Secret is stored encrypted via pgp_sym_encrypt — never stored in plaintext.
    const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: endpointId } })
    if (!endpoint) {
      throw new UnrecoverableError(`Webhook endpoint ${endpointId} not found.`)
    }
    const rawSecret = await decryptWebhookSecret(endpoint.secretEncrypted)

    // §7 HMAC signature: "<timestamp>.<json_payload>"
    const timestamp = Math.floor(Date.now() / 1000).toString()
    const signaturePayload = `${timestamp}.${delivery.payload}`
    const hmac = crypto.createHmac('sha256', rawSecret)
    hmac.update(signaturePayload)
    const signature = hmac.digest('hex')

    let success = false
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vouchflow-Signature': `t=${timestamp},v1=${signature}`,
        },
        body: delivery.payload,
        signal: AbortSignal.timeout(10_000),
      })
      success = response.ok
    } catch {
      success = false
    }

    if (success) {
      await prisma.webhookDelivery.update({ where: { id: deliveryId }, data: { status: 'delivered' } })
    } else {
      const isLastAttempt = job.attemptsMade >= WEBHOOK_DELAYS_MS.length - 1
      if (isLastAttempt) {
        // §7: final state after all retries exhausted = webhook_failed
        await prisma.webhookDelivery.update({ where: { id: deliveryId }, data: { status: 'webhook_failed' } })
        throw new UnrecoverableError('Webhook delivery failed after all retry attempts.')
      }
      throw new Error('Webhook delivery failed, will retry.')
    }
  },
  {
    connection: redis,
    concurrency: 10,
    settings: {
      // Custom backoff implements the §7 retry schedule
      backoffStrategy: (attemptsMade: number) => {
        return WEBHOOK_DELAYS_MS[Math.min(attemptsMade, WEBHOOK_DELAYS_MS.length - 1)]
      },
    },
  },
)

anomalyWorker.on('failed', (job, err) => {
  console.error(`[anomaly] job ${job?.id} failed:`, err.message)
})

webhookWorker.on('failed', (job, err) => {
  if (!(err instanceof UnrecoverableError)) {
    console.error(`[webhooks] job ${job?.id} failed:`, err.message)
  }
})

console.log('[worker] Anomaly and webhook workers started.')

const shutdown = async () => {
  await anomalyWorker.close()
  await webhookWorker.close()
  await prisma.$disconnect()
  process.exit(0)
}

process.on('SIGTERM', shutdown)
process.on('SIGINT', shutdown)
