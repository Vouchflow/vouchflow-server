import { prisma } from '../lib/prisma.js'

// §15 anomaly scoring. Pulled out of the old BullMQ workers/index.ts in favour
// of inline execution from enroll/verify. The whole computation is a handful
// of Prisma queries; running it on the request thread adds <50ms and lets us
// stop running a worker process + an Upstash queue.
//
// Caller pattern: `void scoreAnomaly(...).catch(...)` — don't await it on the
// hot path, and don't fail the request if it throws. The data we score over
// is all in Postgres, so a crash mid-score just means the row keeps its old
// (or null) riskScore until the next enroll/verify recomputes it. Acceptable
// loss vs. the cost of a queue.

export async function scoreAnomaly(params: { keyFingerprint: string }): Promise<void> {
  const networkDevice = await prisma.networkDevice.findUnique({
    where: { keyFingerprint: params.keyFingerprint },
  })
  if (!networkDevice) return

  const now = new Date()
  const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
  const last7Days  = new Date(now.getTime() - 7  * 24 * 60 * 60 * 1000)

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
}
