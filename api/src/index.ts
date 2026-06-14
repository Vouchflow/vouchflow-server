import { buildApp } from './app.js'
import { config } from './config.js'
import { prisma } from './lib/prisma.js'
import { retryPendingWebhooks } from './services/webhooks.js'

// Webhook retry cadence. Picked to be slow enough that the §7 5-second
// initial retry isn't dominated by tick jitter (worst case is a 30s wait
// for an attempt that should have happened ~25s ago — fine for a webhook),
// and fast enough that catastrophe recovery doesn't take an hour.
const WEBHOOK_RETRY_TICK_MS = 30_000

async function main() {
  const app = await buildApp()

  await app.listen({ port: config.port, host: config.host })

  // The BullMQ worker process used to own this; we deleted it (Upstash bill,
  // see services/webhooks.ts). One tick per api-server instance is sufficient —
  // each tick claims at most 50 rows and they're idempotent, so even if we
  // ever run more than one instance the worst case is duplicate POSTs to the
  // integrator's endpoint, which they should already tolerate by HMAC + event id.
  const webhookTick = setInterval(() => {
    retryPendingWebhooks().catch((err) => {
      console.error(`[webhooks] retry tick threw: ${err.message}`)
    })
  }, WEBHOOK_RETRY_TICK_MS)
  webhookTick.unref()

  const shutdown = async () => {
    clearInterval(webhookTick)
    await app.close()
    await prisma.$disconnect()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
